from gevent import monkey
monkey.patch_all()

import os
import json
import hashlib
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room

# -- App setup --
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///securechat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# -- Database Models --
class User(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    username        = db.Column(db.String(80), unique=True, nullable=False)
    password_hash   = db.Column(db.String(128), nullable=False)
    public_key      = db.Column(db.Text, nullable=False)
    private_key_enc = db.Column(db.Text, nullable=False)

class Message(db.Model):
    id                     = db.Column(db.Integer, primary_key=True)
    sender                 = db.Column(db.String(80), nullable=False)
    recipient              = db.Column(db.String(80), nullable=False)
    enc_session_key        = db.Column(db.Text, nullable=False) # for recipient
    sender_enc_session_key = db.Column(db.Text, nullable=True)  # for sender
    nonce                  = db.Column(db.Text, nullable=False)
    tag                    = db.Column(db.Text, nullable=False)
    ciphertext             = db.Column(db.Text, nullable=False)
    timestamp              = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# -- Auth Helpers --
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# -- Routes --
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    user     = User.query.filter_by(username=username).first()
    if not user or user.password_hash != hash_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    session['username'] = username
    return jsonify({
        'ok': True,
        'private_key_enc': user.private_key_enc
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data            = request.get_json()
    username        = data.get('username', '').strip().lower()
    password        = data.get('password', '')
    public_key      = data.get('public_key')
    private_key_enc = data.get('private_key_enc')

    if not username or not password or not public_key or not private_key_enc:
        return jsonify({'error': 'All fields required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409

    user = User(
        username        = username,
        password_hash   = hash_password(password),
        public_key      = public_key,
        private_key_enc = private_key_enc
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

# -- API --
@app.route('/api/users')
def api_users():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    users = [u.username for u in User.query.all() if u.username != session['username']]
    return jsonify({'users': users})

@app.route('/api/public_key/<username>')
def api_public_key(username):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'public_key': user.public_key})

@app.route('/api/send', methods=['POST'])
def api_send():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    recipient = data.get('recipient', '').strip().lower()
    
    msg = Message(
        sender                 = session['username'],
        recipient              = recipient,
        enc_session_key        = data.get('enc_session_key'),
        sender_enc_session_key = data.get('sender_enc_session_key'),
        nonce                  = data.get('nonce'),
        tag                    = data.get('tag'),
        ciphertext             = data.get('ciphertext')
    )
    db.session.add(msg)
    db.session.commit()

    socketio.emit('new_message', {
        'id':        msg.id,
        'sender':    msg.sender,
        'recipient': msg.recipient,
        'timestamp': msg.timestamp.isoformat()
    }, room=recipient)
    
    # Also emit to sender so their other tabs sync
    socketio.emit('new_message', {
        'id':        msg.id,
        'sender':    msg.sender,
        'recipient': msg.recipient,
        'timestamp': msg.timestamp.isoformat()
    }, room=session['username'])

    return jsonify({'ok': True, 'id': msg.id})

@app.route('/api/messages/<contact>')
def api_messages(contact):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    me = session['username']
    msgs = Message.query.filter(
        db.or_(
            db.and_(Message.sender == contact, Message.recipient == me),
            db.and_(Message.sender == me,      Message.recipient == contact)
        )
    ).order_by(Message.timestamp).all()
    
    result = []
    for m in msgs:
        # If I am the recipient, I use enc_session_key
        # If I am the sender, I use sender_enc_session_key
        key_to_use = m.enc_session_key if m.recipient == me else m.sender_enc_session_key
        result.append({
            'id':              m.id,
            'sender':          m.sender,
            'recipient':       m.recipient,
            'enc_session_key': key_to_use,
            'nonce':           m.nonce,
            'tag':             m.tag,
            'ciphertext':      m.ciphertext,
            'timestamp':       m.timestamp.isoformat()
        })
    return jsonify({'messages': result})

@socketio.on('join')
def on_join(data):
    room = data.get('username')
    if room:
        join_room(room)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5010))
    print(f"Server starting on port {port}...")
    socketio.run(app, host='0.0.0.0', port=port, debug=True, use_reloader=False)
