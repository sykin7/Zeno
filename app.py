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
socketio = SocketIO(app, cors_allowed_origins="*")

DB_PATH = os.path.join('data', 'users.db')
connected_users = {}
auth_tokens = {}
message_limits = {}
auth_limits = {}

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('data', exist_ok=True)
    conn = get_db()
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA auto_vacuum = FULL;')
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (uid TEXT PRIMARY KEY, nickname TEXT, password_hash TEXT, public_key TEXT)''')
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
        return jsonify({'error': '请求频率过快，请稍后再试'}), 429
    auth_limits[ip] = now

    data = request.json
    nickname = data.get('nickname')
    password = data.get('password')
    public_key = data.get('public_key')
    
    if not nickname or not password or not public_key:
        return jsonify({'error': '缺少参数'}), 400
        
    conn = get_db()
    
    while True:
        uid = str(random.randint(10000000, 99999999))
        existing = conn.execute('SELECT 1 FROM users WHERE uid = ?', (uid,)).fetchone()
        if not existing:
            break
            
    pwd_hash = generate_password_hash(password)
    conn.execute('INSERT INTO users (uid, nickname, password_hash, public_key) VALUES (?, ?, ?, ?)',
                 (uid, nickname, pwd_hash, public_key))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok', 'uid': uid})

@app.route('/api/login', methods=['POST'])
def login():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = time.time()
    if now - auth_limits.get(ip, 0) < 2.0:
        return jsonify({'error': '请求频率过快，请稍后再试'}), 429
    auth_limits[ip] = now

    data = request.json
    uid = data.get('uid')
    password = data.get('password')
    
    conn = get_db()
    user = conn.execute('SELECT nickname, password_hash, public_key FROM users WHERE uid = ?', (uid,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        token = secrets.token_hex(16)
        auth_tokens[uid] = token
        return jsonify({'status': 'ok', 'uid': uid, 'nickname': user['nickname'], 'public_key': user['public_key'], 'token': token})
    return jsonify({'error': 'UID 或密码错误'}), 401

@app.route('/api/contact', methods=['POST'])
def add_contact():
    data = request.json
    target_uid = data.get('uid')
    
    conn = get_db()
    user = conn.execute('SELECT nickname, public_key FROM users WHERE uid = ?', (target_uid,)).fetchone()
    conn.close()
    
    if user:
        return jsonify({'status': 'ok', 'uid': target_uid, 'nickname': user['nickname'], 'public_key': user['public_key']})
    return jsonify({'error': '未找到该 UID 对应的用户'}), 404

@socketio.on('connect')
def handle_connect():
    pass

@socketio.on('register_socket')
def handle_register(data):
    uid = data.get('uid')
    token = data.get('token')
    
    if uid and auth_tokens.get(uid) == token:
        connected_users[uid] = request.sid
        emit('online_users', {'users': list(connected_users.keys())}, to=request.sid)
        emit('user_status', {'uid': uid, 'status': 'online'}, broadcast=True)
    else:
        emit('auth_failed', {'error': '认证过期或服务器已重启，请重新登录'}, to=request.sid)
        disconnect()

@socketio.on('disconnect')
def handle_disconnect():
    for uid, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[uid]
            emit('user_status', {'uid': uid, 'status': 'offline'}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    sender_uid = data.get('from')
    token = data.get('token')
    target_uid = data.get('to')
    payload = data.get('payload')
    
    if not sender_uid or auth_tokens.get(sender_uid) != token:
        return
        
    now = time.time()
    last_time = message_limits.get(sender_uid, 0)
    if now - last_time < 0.5:
        emit('message_error', {'status': '频率限制', 'to': target_uid, 'msg': '发送频率过快，请减速'}, to=request.sid)
        return
    message_limits[sender_uid] = now

    if target_uid in connected_users:
        target_sid = connected_users[target_uid]
        emit('receive_message', {'from': sender_uid, 'payload': payload, 'timestamp': now * 1000}, room=target_sid)
    else:
        emit('message_error', {'status': '离线', 'to': target_uid, 'msg': '由于对方离线拦截失败，消息已丢失'}, to=request.sid)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8787)
