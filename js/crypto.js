// js/crypto.js — E2EE primitives using the browser's Web Crypto API

// ---- 1. Generate an X25519 keypair (one per user, created once at signup) ----
export async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    { name: "X25519" },
    true, // extractable: we need to export the public key
    ["deriveKey", "deriveBits"],
  );
}

// ---- 2. Export the PUBLIC key so we can send it to the server ----
export async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw))); // base64
}

// ---- 3. Import someone else's public key from base64 ----
export async function importPublicKey(base64) {
  const raw = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  return await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "X25519" },
    true,
    [],
  );
}

// ---- 4. Derive the SAME shared AES key from (my private, their public) ----
export async function deriveSharedKey(myPrivateKey, theirPublicKey) {
  return await crypto.subtle.deriveKey(
    { name: "X25519", public: theirPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: 256 },
    false, // not extractable — good, keep it secret
    ["encrypt", "decrypt"],
  );
}

// ---- 5. Encrypt a string. Returns { iv, ciphertext } both base64 ----
export async function encryptMessage(sharedKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedKey,
    encoded,
  );
  return {
    iv: btoa(String.fromCharCode(...iv)),
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(cipherBuf))),
  };
}

// ---- 6. Decrypt. Takes the same { iv, ciphertext } shape ----
export async function decryptMessage(sharedKey, { iv, ciphertext }) {
  const ivBytes = Uint8Array.from(atob(iv), (c) => c.charCodeAt(0));
  const ctBytes = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivBytes },
    sharedKey,
    ctBytes,
  );
  return new TextDecoder().decode(plainBuf);
}
