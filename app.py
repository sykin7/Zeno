from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit, disconnect
import sqlite3
import os
import secrets
import time
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=10485760, ping_timeout=10, ping_interval=5)

DB_PATH = os.path.join('data', 'users.db')
connected_users = {}
auth_tokens = {}
message_limits = {}
auth_limits = {}
ip_reg_counts = {}

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('data', exist_ok=True)
    conn = get_db()
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA auto_vacuum = FULL;')
    conn.execute('CREATE TABLE IF NOT EXISTS users (uid TEXT PRIMARY KEY, nickname TEXT, password_hash TEXT, public_key TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS offline_msgs (id INTEGER PRIMARY KEY AUTOINCREMENT, to_uid TEXT, from_uid TEXT, payload TEXT, timestamp REAL)')
    conn.execute('CREATE TABLE IF NOT EXISTS friend_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, to_uid TEXT, from_uid TEXT, payload TEXT, timestamp REAL)')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = time.time()
    
    if now - auth_limits.get(ip, 0) < 2.0:
        return jsonify({'error': '操作过于频繁'}), 429
    auth_limits[ip] = now
    
    if ip not in ip_reg_counts:
        ip_reg_counts[ip] = {'count': 0, 'reset_time': now + 86400}
    if now > ip_reg_counts[ip]['reset_time']:
        ip_reg_counts[ip] = {'count': 0, 'reset_time': now + 86400}
    if ip_reg_counts[ip]['count'] >= 3:
        return jsonify({'error': '该IP今日注册次数已达安全限制'}), 403

    data = request.json
    nickname, password, public_key = data.get('nickname'), data.get('password'), data.get('public_key')
    
    if not nickname or not password or not public_key:
        return jsonify({'error': 'Missing'}), 400
        
    conn = get_db()
    
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if total_users >= 5000:
        conn.close()
        return jsonify({'error': '系统注册容量已满，暂停新用户开放'}), 503

    while True:
        uid = str(random.randint(10000000, 99999999))
        if not conn.execute('SELECT 1 FROM users WHERE uid = ?', (uid,)).fetchone(): break
        
    pwd_hash = generate_password_hash(password)
    conn.execute('INSERT INTO users (uid, nickname, password_hash, public_key) VALUES (?, ?, ?, ?)', (uid, nickname, pwd_hash, public_key))
    conn.commit()
    conn.close()
    
    ip_reg_counts[ip]['count'] += 1
    return jsonify({'status': 'ok', 'uid': uid})

@app.route('/api/login', methods=['POST'])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = time.time()
    if now - auth_limits.get(ip, 0) < 2.0:
        return jsonify({'error': '操作过于频繁'}), 429
    auth_limits[ip] = now
    data = request.json
    uid, password = data.get('uid'), data.get('password')
    conn = get_db()
    user = conn.execute('SELECT nickname, password_hash, public_key FROM users WHERE uid = ?', (uid,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password_hash'], password):
        token = secrets.token_hex(16)
        auth_tokens[uid] = token
        return jsonify({'status': 'ok', 'uid': uid, 'nickname': user['nickname'], 'public_key': user['public_key'], 'token': token})
    return jsonify({'error': 'Auth failed'}), 401

@app.route('/api/search_user', methods=['POST'])
def search_user():
    data = request.json
    target_uid = data.get('uid')
    conn = get_db()
    user = conn.execute('SELECT nickname, public_key FROM users WHERE uid = ?', (target_uid,)).fetchone()
    conn.close()
    if user: return jsonify({'status': 'ok', 'uid': target_uid, 'nickname': user['nickname'], 'public_key': user['public_key']})
    return jsonify({'error': '用户不存在'}), 404

@app.route('/api/profile/update', methods=['POST'])
def update_profile():
    data = request.json
    uid, token, nickname = data.get('uid'), data.get('token'), data.get('nickname')
    if not uid or auth_tokens.get(uid) != token: return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db()
    conn.execute('UPDATE users SET nickname = ? WHERE uid = ?', (nickname, uid))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

@socketio.on('register_socket')
def handle_register(data):
    uid, token = data.get('uid'), data.get('token')
    if uid and auth_tokens.get(uid) == token:
        connected_users[uid] = request.sid
        emit('online_users', {'users': list(connected_users.keys())}, to=request.sid)
        emit('user_status', {'uid': uid, 'status': 'online'}, broadcast=True)
        
        conn = get_db()
        
        # 核心优化：全站离线消息 7 天强制过期粉碎（防数据库膨胀）
        # 604800 秒 = 7天，乘以 1000 转换为毫秒时间戳
        expire_time_ms = (time.time() - 604800) * 1000
        conn.execute('DELETE FROM offline_msgs WHERE timestamp < ?', (expire_time_ms,))
        
        # 提取属于该用户的离线消息
        offline_msgs = conn.execute('SELECT from_uid, payload, timestamp FROM offline_msgs WHERE to_uid = ? ORDER BY timestamp ASC', (uid,)).fetchall()
        if offline_msgs:
            emit('offline_sync', [{'from': m['from_uid'], 'payload': m['payload'], 'timestamp': m['timestamp']} for m in offline_msgs], to=request.sid)
            # 发送完毕后，精准销毁该用户的离线消息
            conn.execute('DELETE FROM offline_msgs WHERE to_uid = ?', (uid,))
            
        conn.commit()
        conn.close()
    else: 
        disconnect()

@socketio.on('disconnect')
def handle_disconnect():
    for uid, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[uid]
            emit('user_status', {'uid': uid, 'status': 'offline'}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    sender_uid, token, target_uid, payload = data.get('from'), data.get('token'), data.get('to'), data.get('payload')
    if not sender_uid or auth_tokens.get(sender_uid) != token: return
    now = time.time()
    if now - message_limits.get(sender_uid, 0) < 0.5: return
    message_limits[sender_uid] = now
    now_ms = now * 1000
    if target_uid in connected_users:
        emit('receive_message', {'from': sender_uid, 'payload': payload, 'timestamp': now_ms}, room=connected_users[target_uid])
    else:
        conn = get_db()
        conn.execute('INSERT INTO offline_msgs (to_uid, from_uid, payload, timestamp) VALUES (?, ?, ?, ?)', (target_uid, sender_uid, payload, now_ms))
        conn.commit()
        conn.close()

@socketio.on('send_friend_request')
def handle_send_friend_request(data):
    sender_uid, token, target_uid, payload = data.get('from'), data.get('token'), data.get('to'), data.get('payload')
    if not sender_uid or auth_tokens.get(sender_uid) != token: return
    conn = get_db()
    existing = conn.execute('SELECT 1 FROM friend_requests WHERE to_uid = ? AND from_uid = ?', (target_uid, sender_uid)).fetchone()
    if not existing:
        conn.execute('INSERT INTO friend_requests (to_uid, from_uid, payload, timestamp) VALUES (?, ?, ?, ?)', (target_uid, sender_uid, payload, time.time()))
        conn.commit()
    conn.close()
    if target_uid in connected_users:
        emit('new_friend_request', {'from': sender_uid}, room=connected_users[target_uid])

@socketio.on('fetch_friend_requests')
def handle_fetch_requests(data):
    uid, token = data.get('uid'), data.get('token')
    if not uid or auth_tokens.get(uid) != token: return
    conn = get_db()
    expire_time = time.time() - 604800
    conn.execute('DELETE FROM friend_requests WHERE timestamp < ?', (expire_time,))
    conn.commit()
    reqs = conn.execute('SELECT id, from_uid, payload, timestamp FROM friend_requests WHERE to_uid = ? ORDER BY timestamp DESC', (uid,)).fetchall()
    conn.close()
    emit('friend_requests_data', [{'id': r['id'], 'from': r['from_uid'], 'payload': r['payload'], 'ts': r['timestamp'] * 1000} for r in reqs], to=request.sid)

@socketio.on('resolve_friend_request')
def handle_resolve_request(data):
    uid, token, req_id = data.get('uid'), data.get('token'), data.get('req_id')
    if not uid or auth_tokens.get(uid) != token: return
    conn = get_db()
    conn.execute('DELETE FROM friend_requests WHERE id = ? AND to_uid = ?', (req_id, uid))
    conn.commit()
    conn.close()

@socketio.on('msg_ack')
def handle_ack(data):
    if auth_tokens.get(data.get('from')) == data.get('token') and data.get('to') in connected_users:
        emit('msg_ack', {'msgId': data.get('msgId'), 'from': data.get('from')}, room=connected_users[data.get('to')])

@socketio.on('msg_read')
def handle_read(data):
    if auth_tokens.get(data.get('from')) == data.get('token') and data.get('to') in connected_users:
        emit('msg_read', {'msgId': data.get('msgId'), 'from': data.get('from')}, room=connected_users[data.get('to')])

@socketio.on('webrtc_signal')
def handle_webrtc(data):
    if auth_tokens.get(data.get('from')) == data.get('token') and data.get('to') in connected_users:
        emit('webrtc_signal', data, room=connected_users[data.get('to')])

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8787)
