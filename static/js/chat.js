/* chat.js — all client-side chat logic with True E2EE */

let currentContact = null;
let allUsers       = [];
let privateKey     = null;
let myPublicKey    = null;
const socket       = io();

// ── Init ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  const ok = await initCrypto();
  if (!ok) {
    alert("Session expired or decryption failed. Please log in again.");
    window.location.href = "/login";
    return;
  }

  loadUsers();
  socket.emit('join', { username: ME });

  // Real-time: new message arrives
  socket.on('new_message', (data) => {
    // Both sender and recipient get this event now
    if (data.sender === currentContact || data.recipient === currentContact) {
      loadMessages(currentContact);
    }
    // Flash the user in sidebar if not currently open
    if (data.sender !== ME && data.sender !== currentContact) {
      markUnread(data.sender);
    }
  });
});

/**
 * Unwrap the private key stored in sessionStorage
 */
async function initCrypto() {
  const pwd = sessionStorage.getItem('temp_pwd');
  const wrapped = sessionStorage.getItem('wrapped_pk');
  if (!pwd || !wrapped) return false;

  try {
    privateKey = await unwrapPrivateKey(wrapped, pwd);
    // Fetch my own public key to allow "double encryption" (for self)
    const res = await fetch(`/api/public_key/${ME}`);
    const data = await res.json();
    myPublicKey = data.public_key;
    
    // Clear the sensitive temporary password from memory/storage
    sessionStorage.removeItem('temp_pwd');
    return true;
  } catch (e) {
    console.error("Failed to unwrap private key", e);
    return false;
  }
}

// ── Load user list from API ───────────────────────────────────
async function loadUsers() {
  try {
    const res  = await fetch('/api/users');
    const data = await res.json();
    allUsers   = data.users || [];
    renderUserList(allUsers);
  } catch (e) {
    console.error('Failed to load users', e);
  }
}

function renderUserList(users) {
  const ul = document.getElementById('userList');
  ul.innerHTML = '';
  if (users.length === 0) {
    ul.innerHTML = '<li style="padding:14px 18px;font-size:13px;color:var(--text-soft)">No other users yet</li>';
    return;
  }
  users.forEach(u => {
    const li = document.createElement('li');
    li.className = 'user-item' + (u === currentContact ? ' active' : '');
    li.dataset.username = u;
    li.innerHTML = `
      <div class="user-avatar">${u[0]}</div>
      <span class="user-name">${u}</span>
    `;
    li.onclick = () => openChat(u);
    ul.appendChild(li);
  });
}

function filterUsers(q) {
  const filtered = allUsers.filter(u => u.toLowerCase().includes(q.toLowerCase()));
  renderUserList(filtered);
}

function markUnread(username) {
  const item = document.querySelector(`.user-item[data-username="${username}"]`);
  if (item) item.style.fontWeight = '600';
}

// ── Open a conversation ───────────────────────────────────────
function openChat(username) {
  currentContact = username;

  // Update sidebar active state
  document.querySelectorAll('.user-item').forEach(li => {
    li.classList.toggle('active', li.dataset.username === username);
  });

  // Show chat window
  document.getElementById('chatEmpty').style.display  = 'none';
  document.getElementById('chatWindow').style.display = 'flex';

  // Set header
  document.getElementById('chatName').textContent   = username;
  document.getElementById('chatAvatar').textContent = username[0].toUpperCase();

  loadMessages(username);
}

// ── Load messages ─────────────────────────────────────────────
async function loadMessages(contact) {
  const area    = document.getElementById('messagesArea');
  const loading = document.getElementById('loadingMsgs');
  loading.style.display = 'block';

  try {
    const res  = await fetch(`/api/messages/${contact}`);
    const data = await res.json();
    await renderMessages(data.messages || []);
  } catch (e) {
    area.innerHTML = '<p style="text-align:center;color:var(--text-soft);font-size:13px">Failed to load messages</p>';
  } finally {
    loading.style.display = 'none';
  }
}

async function renderMessages(messages) {
  const area = document.getElementById('messagesArea');
  area.innerHTML = '';

  if (messages.length === 0) {
    area.innerHTML = `<div style="text-align:center;padding:40px 20px">
      <p style="font-size:13px;color:var(--text-soft)">No messages yet. Say hello! 👋</p>
    </div>`;
    return;
  }

  let lastDate = '';
  for (const msg of messages) {
    const dt   = new Date(msg.timestamp);
    const date = dt.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });

    if (date !== lastDate) {
      const div = document.createElement('div');
      div.className   = 'date-divider';
      div.textContent = date;
      area.appendChild(div);
      lastDate = date;
    }

    const isSent = msg.sender === ME;
    const row    = document.createElement('div');
    row.className = 'msg-row ' + (isSent ? 'sent' : 'recv');

    const time = dt.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });

    // Decrypt the message locally
    let text = "";
    try {
      text = await decryptMessage(msg, privateKey);
    } catch (e) {
      console.error("Decryption failed", e);
      text = "[Decryption failed — key error]";
    }

    const escapedText = escapeHtml(text);
    row.innerHTML = `
      <div class="msg-bubble">
        ${escapedText}
        <span class="msg-time">${time}</span>
      </div>`;
    area.appendChild(row);
  }

  // Scroll to bottom
  area.scrollTop = area.scrollHeight;
}

// ── Send a message ────────────────────────────────────────────
async function sendMessage() {
  const input = document.getElementById('msgInput');
  const text  = input.value.trim();
  if (!text || !currentContact) return;

  input.value = '';
  autoResize(input);

  try {
    // 1. Get recipient's public key
    const resKey = await fetch(`/api/public_key/${currentContact}`);
    const keyData = await resKey.json();
    if (!keyData.public_key) throw new Error("Recipient public key not found");

    // 2. Encrypt locally for both recipient and myself
    const encData = await encryptMessage(text, keyData.public_key, myPublicKey);

    // 3. Send encrypted blobs to server
    const res  = await fetch('/api/send', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ 
        recipient: currentContact, 
        ...encData
      })
    });
    const data = await res.json();
    if (!data.ok) {
      alert('Failed to send: ' + (data.error || 'Unknown error'));
      input.value = text;
    }
    // Note: We don't optimistic append anymore, we wait for the socket event
    // to ensure the message was stored and synchronized.
  } catch (e) {
    console.error(e);
    alert('Encryption or Network error. Message not sent.');
    input.value = text;
  }
}

// ── Keyboard shortcut: Enter to send, Shift+Enter for newline ─
function handleKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

// ── Auto-resize textarea ──────────────────────────────────────
function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

// ── XSS protection ────────────────────────────────────────────
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/\n/g, '<br>');
}
