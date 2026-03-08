from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

DB_PATH = os.path.join('data', 'users.db')
connected_users = {}

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs('data', exist_ok=True)
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (username TEXT PRIMARY KEY, password_hash TEXT, public_key TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    public_key = data.get('public_key')
    
    if not username or not password or not public_key:
        return jsonify({'error': '缺少参数'}), 400
        
    conn = get_db()
    existing = conn.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': '用户已存在'}), 409
        
    pwd_hash = generate_password_hash(password)
    conn.execute('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)',
                 (username, pwd_hash, public_key))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    user = conn.execute('SELECT password_hash, public_key FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password_hash'], password):
        return jsonify({'status': 'ok', 'public_key': user['public_key']})
    return jsonify({'error': '账号或密码错误'}), 401

@app.route('/api/users', methods=['GET'])
def get_users():
    conn = get_db()
    users = conn.execute('SELECT username, public_key FROM users').fetchall()
    conn.close()
    
    result = []
    for user in users:
        uname = user['username']
        result.append({
            'username': uname,
            'public_key': user['public_key'],
            'online': uname in connected_users
        })
    return jsonify(result)

@socketio.on('connect')
def handle_connect():
    pass

@socketio.on('register_socket')
def handle_register(data):
    username = data.get('username')
    if username:
        connected_users[username] = request.sid
        emit('user_status', {'username': username, 'status': 'online'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    for uname, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[uname]
            emit('user_status', {'username': uname, 'status': 'offline'}, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    target = data.get('to')
    payload = data.get('payload')
    sender = data.get('from')
    
    if target in connected_users:
        target_sid = connected_users[target]
        emit('receive_message', {'from': sender, 'payload': payload}, room=target_sid)
    else:
        emit('message_error', {'status': '离线', 'to': target})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8787)
