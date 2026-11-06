// BONELİA AI password vault — the cryptography that runs on the owner's phone (user request 06.11.2026).
// The panel is opened over Tailscale (http://100.x…), where browsers switch WebCrypto off, so the audited
// @noble libraries (MIT) are bundled into server/static/vault.js. Must match src/bonelia/security/vault.py.
//
// Vault:  a random X25519 key pair. The private key is wrapped with AES-256-GCM under
//         scrypt(master password); only the phone ever unwraps it. The server keeps public key + wrapped key.
// Entry:  sealed box to the vault's public key: ephemeral X25519, HKDF-SHA256, AES-256-GCM.
//         Agents seal new RustDesk passwords the same way, so they never see or store a readable password.
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, utf8ToBytes, bytesToUtf8 } from '@noble/ciphers/utils.js';

const KEY_AAD = 'bonelia-vault-key-v1|';
const BOX_INFO = 'bonelia-vault-box-v1';
const KDF = { n: 32768, r: 8, p: 1 };

const b64 = (u8) => { let s = ''; for (const c of u8) s += String.fromCharCode(c); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(String(s)), (c) => c.charCodeAt(0));
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

async function masterKey(password, kdf, onProgress) {
  return scryptAsync(utf8ToBytes(password.normalize('NFC')), unb64(kdf.salt),
    { N: kdf.n, r: kdf.r, p: kdf.p, dkLen: 32, asyncTick: 20, onProgress });
}

/** New vault for a master password: what the server stores (nothing in it is readable without the password). */
export async function create(password, onProgress) {
  const priv = randomBytes(32), pub = x25519.getPublicKey(priv);
  const kdf = { alg: 'scrypt', ...KDF, salt: b64(randomBytes(16)) };
  const nonce = randomBytes(12);
  const ct = gcm(await masterKey(password, kdf, onProgress), nonce, utf8ToBytes(KEY_AAD + b64(pub))).encrypt(priv);
  return { v: 1, kdf, pub: b64(pub), wrap: { nonce: b64(nonce), ct: b64(ct) } };
}

/** The private key, or an Error('wrong_password'). */
export async function unlock(meta, password, onProgress) {
  const pub = unb64(meta.pub);
  let priv;
  try {
    priv = gcm(await masterKey(password, meta.kdf, onProgress), unb64(meta.wrap.nonce), utf8ToBytes(KEY_AAD + meta.pub))
      .decrypt(unb64(meta.wrap.ct));
  } catch { throw new Error('wrong_password'); }
  if (!same(x25519.getPublicKey(priv), pub)) throw new Error('wrong_password');
  return priv;
}

function boxKey(shared, epk, pub) { return hkdf(sha256, shared, cat(epk, pub), utf8ToBytes(BOX_INFO), 32); }

export function seal(pubB64, obj) {
  const pub = unb64(pubB64), eph = randomBytes(32), epk = x25519.getPublicKey(eph);
  const nonce = randomBytes(12);
  const ct = gcm(boxKey(x25519.getSharedSecret(eph, pub), epk, pub), nonce, utf8ToBytes(BOX_INFO))
    .encrypt(utf8ToBytes(JSON.stringify(obj)));
  return { v: 1, epk: b64(epk), nonce: b64(nonce), ct: b64(ct) };
}

export function open(priv, box) {
  const epk = unb64(box.epk), pub = x25519.getPublicKey(priv);
  const pt = gcm(boxKey(x25519.getSharedSecret(priv, epk), epk, pub), unb64(box.nonce), utf8ToBytes(BOX_INFO))
    .decrypt(unb64(box.ct));
  return JSON.parse(bytesToUtf8(pt));
}

/** Letters and digits only (RustDesk accepts them everywhere), no look-alikes, uniform. */
export function randomPassword(length = 16) {
  const abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  let out = '';
  while (out.length < length) for (const b of randomBytes(32)) if (b < 228 && out.length < length) out += abc[b % 57];
  return out;
}

globalThis.BoneliaVault = { create, unlock, seal, open, randomPassword };
