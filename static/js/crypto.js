/**
 * crypto.js — Client-side E2EE helpers using Web Crypto API (SubtleCrypto)
 * This handles key generation, wrapping/unwrapping, and encryption/decryption.
 */

/**
 * Generate a new RSA-OAEP key pair for E2EE.
 */
async function generateKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true, // extractable
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}

/**
 * Export a public key to PEM-like base64 format for the server.
 */
async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey("spki", key);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

/**
 * Import a PEM public key.
 */
async function importPublicKey(pem) {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\n/g, "");
  const binary = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return await window.crypto.subtle.importKey(
    "spki",
    binary,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt", "wrapKey"]
  );
}

/**
 * Wrap (encrypt) a private key with a password-derived key.
 */
async function wrapPrivateKey(privateKey, password) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const masterKey = await deriveKeyFromPassword(password, salt);
  
  const wrapped = await window.crypto.subtle.wrapKey(
    "pkcs8",
    privateKey,
    masterKey,
    { name: "AES-GCM", iv: salt } // Use salt as IV for simplicity in this demo
  );
  
  // Return salt + wrapped data as base64
  const combined = new Uint8Array(salt.length + wrapped.byteLength);
  combined.set(salt);
  combined.set(new Uint8Array(wrapped), salt.length);
  return btoa(String.fromCharCode(...combined));
}

/**
 * Unwrap (decrypt) a private key using a password.
 */
async function unwrapPrivateKey(wrappedB64, password) {
  const combined = Uint8Array.from(atob(wrappedB64), c => c.charCodeAt(0));
  const salt = combined.slice(0, 16);
  const wrapped = combined.slice(16);
  
  const masterKey = await deriveKeyFromPassword(password, salt);
  
  return await window.crypto.subtle.unwrapKey(
    "pkcs8",
    wrapped,
    masterKey,
    { name: "AES-GCM", iv: salt },
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt", "unwrapKey"]
  );
}

/**
 * Derive a 256-bit AES-GCM key from a password.
 */
async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"]
  );
}

/**
 * Encrypt a message for both recipient and sender.
 * Uses a random session key (AES-GCM) which is wrapped with RSA-OAEP.
 */
async function encryptMessage(text, recipientPublicKeyPem, myPublicKeyPem) {
  const sessionKey = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    sessionKey,
    enc.encode(text)
  );
  
  const recipientKey = await importPublicKey(recipientPublicKeyPem);
  const myKey        = await importPublicKey(myPublicKeyPem);
  
  const wrappedForRecipient = await window.crypto.subtle.wrapKey("raw", sessionKey, recipientKey, { name: "RSA-OAEP" });
  const wrappedForMe        = await window.crypto.subtle.wrapKey("raw", sessionKey, myKey,        { name: "RSA-OAEP" });
  
  // Extract tag from AES-GCM (SubtleCrypto appends it to the ciphertext)
  const fullEnc = new Uint8Array(ciphertext);
  const tagSize = 16;
  const actualCiphertext = fullEnc.slice(0, -tagSize);
  const tag = fullEnc.slice(-tagSize);

  return {
    enc_session_key:        btoa(String.fromCharCode(...new Uint8Array(wrappedForRecipient))),
    sender_enc_session_key: btoa(String.fromCharCode(...new Uint8Array(wrappedForMe))),
    nonce:                  btoa(String.fromCharCode(...iv)),
    tag:                    btoa(String.fromCharCode(...tag)),
    ciphertext:             btoa(String.fromCharCode(...actualCiphertext))
  };
}

/**
 * Decrypt a message using my private key.
 */
async function decryptMessage(msg, privateKey) {
  const wrappedKey = Uint8Array.from(atob(msg.enc_session_key), c => c.charCodeAt(0));
  const iv         = Uint8Array.from(atob(msg.nonce), c => c.charCodeAt(0));
  const tag        = Uint8Array.from(atob(msg.tag), c => c.charCodeAt(0));
  const ciphertext = Uint8Array.from(atob(msg.ciphertext), c => c.charCodeAt(0));
  
  const sessionKey = await window.crypto.subtle.unwrapKey(
    "raw",
    wrappedKey,
    privateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    true,
    ["decrypt"]
  );
  
  // Reconstruct ciphertext + tag for SubtleCrypto
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    sessionKey,
    combined
  );
  
  return new TextDecoder().decode(decrypted);
}
