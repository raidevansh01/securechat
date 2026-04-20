import os
import json
import base64
import hashlib
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///securechat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# ── Database Models ───────────────────────────────────────────────────────────
class User(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    # private key encrypted with user's password — stored so user can log in from any device
    private_key_enc = db.Column(db.Text, nullable=False)

class Message(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    sender          = db.Column(db.String(80), nullable=False)
    recipient       = db.Column(db.String(80), nullable=False)
    enc_session_key = db.Column(db.Text, nullable=False)
    nonce           = db.Column(db.Text, nullable=False)
    tag             = db.Column(db.Text, nullable=False)
    ciphertext      = db.Column(db.Text, nullable=False)
    timestamp       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# ── Crypto Helpers ────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """SHA-256 hash of the password (hex string)."""
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(password: str) -> bytes:
    """Derive a 32-byte AES key from the user's password (for wrapping private key)."""
    return hashlib.sha256(password.encode()).digest()

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key().decode(), key.publickey().export_key().decode()

def wrap_private_key(private_key_pem: str, password: str) -> dict:
    """AES-encrypt the private key using the user's password."""
    aes_key = derive_key(password)
    cipher  = AES.new(aes_key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(private_key_pem.encode())
    return {
        'nonce':      base64.b64encode(cipher.nonce).decode(),
        'tag':        base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ct).decode()
    }

def unwrap_private_key(wrapped: dict, password: str) -> str:
    """Decrypt the wrapped private key using the user's password."""
    aes_key = derive_key(password)
    cipher  = AES.new(aes_key, AES.MODE_EAX,
                      nonce=base64.b64decode(wrapped['nonce']))
    return cipher.decrypt_and_verify(
        base64.b64decode(wrapped['ciphertext']),
        base64.b64decode(wrapped['tag'])
    ).decode()

def encrypt_message(plaintext: str, recipient_public_key_pem: str) -> dict:
    session_key = get_random_bytes(16)
    # Encrypt message with AES-EAX
    cipher_aes      = AES.new(session_key, AES.MODE_EAX)
    ct, tag         = cipher_aes.encrypt_and_digest(plaintext.encode())
    # Encrypt session key with recipient's RSA public key
    rsa_key         = RSA.import_key(recipient_public_key_pem)
    cipher_rsa      = PKCS1_OAEP.new(rsa_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return {
        'enc_session_key': base64.b64encode(enc_session_key).decode(),
        'nonce':           base64.b64encode(cipher_aes.nonce).decode(),
        'tag':             base64.b64encode(tag).decode(),
        'ciphertext':      base64.b64encode(ct).decode()
    }

def decrypt_message(enc_data: dict, private_key_pem: str) -> str:
    rsa_key     = RSA.import_key(private_key_pem)
    cipher_rsa  = PKCS1_OAEP.new(rsa_key)
    session_key = cipher_rsa.decrypt(base64.b64decode(enc_data['enc_session_key']))
    cipher_aes  = AES.new(session_key, AES.MODE_EAX,
                          nonce=base64.b64decode(enc_data['nonce']))
    return cipher_aes.decrypt_and_verify(
        base64.b64decode(enc_data['ciphertext']),
        base64.b64decode(enc_data['tag'])
    ).decode()

# ── Auth Routes ───────────────────────────────────────────────────────────────
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
    # Unwrap private key to confirm password is correct, then store in session
    try:
        wrapped = json.loads(user.private_key_enc)
        private_key_pem = unwrap_private_key(wrapped, password)
    except Exception:
        return jsonify({'error': 'Could not decrypt private key'}), 401
    session['username']    = username
    session['private_key'] = private_key_pem   # lives in server-side session (signed cookie)
    return jsonify({'ok': True})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data     = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409
    private_key_pem, public_key_pem = generate_rsa_keys()
    wrapped = wrap_private_key(private_key_pem, password)
    user = User(
        username        = username,
        password_hash   = hash_password(password),
        public_key      = public_key_pem,
        private_key_enc = json.dumps(wrapped)
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ── Chat Page ─────────────────────────────────────────────────────────────────
@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = [u.username for u in User.query.all() if u.username != session['username']]
    return render_template('chat.html', username=session['username'], users=users)

# ── API Routes ────────────────────────────────────────────────────────────────
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
    data      = request.get_json()
    recipient = data.get('recipient', '').strip().lower()
    plaintext = data.get('message', '').strip()
    if not recipient or not plaintext:
        return jsonify({'error': 'Recipient and message required'}), 400
    rec_user = User.query.filter_by(username=recipient).first()
    if not rec_user:
        return jsonify({'error': 'Recipient not found'}), 404
    enc = encrypt_message(plaintext, rec_user.public_key)
    msg = Message(
        sender          = session['username'],
        recipient       = recipient,
        enc_session_key = enc['enc_session_key'],
        nonce           = enc['nonce'],
        tag             = enc['tag'],
        ciphertext      = enc['ciphertext']
    )
    db.session.add(msg)
    db.session.commit()
    # Emit real-time event to recipient's room
    socketio.emit('new_message', {
        'id':        msg.id,
        'sender':    msg.sender,
        'recipient': msg.recipient,
        'timestamp': msg.timestamp.isoformat()
    }, room=recipient)
    return jsonify({'ok': True, 'id': msg.id})

@app.route('/api/messages/<contact>')
def api_messages(contact):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    me      = session['username']
    priv    = session.get('private_key')
    # Messages sent TO me FROM contact, plus messages I sent TO contact
    msgs = Message.query.filter(
        db.or_(
            db.and_(Message.sender == contact,    Message.recipient == me),
            db.and_(Message.sender == me,         Message.recipient == contact)
        )
    ).order_by(Message.timestamp).all()
    result = []
    for m in msgs:
        if m.recipient == me:
            # Decrypt messages sent to me
            try:
                text = decrypt_message({
                    'enc_session_key': m.enc_session_key,
                    'nonce':           m.nonce,
                    'tag':             m.tag,
                    'ciphertext':      m.ciphertext
                }, priv)
            except Exception:
                text = '[decryption failed]'
        else:
            # Messages I sent — we need to re-encrypt for self or just show placeholder
            # For simplicity: re-fetch with my own public key isn't possible here.
            # We mark sent messages differently and show the original plaintext is unavailable
            text = None   # handled in JS as "sent"
        result.append({
            'id':        m.id,
            'sender':    m.sender,
            'recipient': m.recipient,
            'text':      text,
            'timestamp': m.timestamp.isoformat()
        })
    return jsonify({'messages': result})

# ── Socket.IO ─────────────────────────────────────────────────────────────────
@socketio.on('join')
def on_join(data):
    room = data.get('username')
    if room:
        join_room(room)

# ── Startup ───────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
