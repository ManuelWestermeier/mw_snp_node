// Secure Broadcast Node Implementation (Signing & Encryption use same keypair)
// Implements: fixed 1024-byte packets, PoW, AES-256-GCM, Curve25519 key exchange derived from Ed25519 seed, Ed25519 signatures,
// replay protection, dummy traffic, gossip-based broadcast.

const fs = require("fs");
const dgram = require("dgram");
const crypto = require("crypto");
const nacl = require("tweetnacl");
const util = require("tweetnacl-util");

// Constants
const PACKET_SIZE = 1024;
const POW_LEADING_ZERO_BITS = 5;
const SYM_KEY_LEN = 32;
const IV_LEN = 12;
const NONCE_LEN = 24;
const CACHE_TTL_MS = 5 * 60 * 1000;

class SecureBroadcastNode {
  constructor(keyDir, peers = []) {
    this.peers = peers;
    this.socket = dgram.createSocket("udp4");
    this.cache = new Map();
    this.callbacks = [];
    this.running = false;
    this.keyDir = keyDir;
    this._loadOrGenerateKeys();
  }

  _loadOrGenerateKeys() {
    const pkFile = `${this.keyDir}/keypair_pk.txt`;
    const skFile = `${this.keyDir}/keypair_sk.txt`;
    fs.mkdirSync(this.keyDir, { recursive: true });

    if (fs.existsSync(pkFile) && fs.existsSync(skFile)) {
      // Load Ed25519 keypair
      this.signPublicKey = util.decodeBase64(fs.readFileSync(pkFile, "utf8"));
      this.signSecretKey = util.decodeBase64(fs.readFileSync(skFile, "utf8"));
    } else {
      // Generate single Ed25519 keypair
      const kp = nacl.sign.keyPair();
      this.signPublicKey = kp.publicKey;
      this.signSecretKey = kp.secretKey;
      fs.writeFileSync(pkFile, util.encodeBase64(kp.publicKey));
      fs.writeFileSync(skFile, util.encodeBase64(kp.secretKey));
    }

    // Derive Curve25519 keypair from Ed25519 seed (first 32 bytes of secretKey)
    const seed = this.signSecretKey.slice(0, 32);
    const encKp = nacl.box.keyPair.fromSecretKey(seed);
    this.encPublicKey = encKp.publicKey;
    this.encSecretKey = encKp.secretKey;
  }

  onMessage(fn) {
    this.callbacks.push(fn);
  }

  static _meetsPow(hash) {
    const mask = 0xff << (8 - POW_LEADING_ZERO_BITS);
    return (hash[0] & mask) === 0;
  }

  _makePacket(data, includeIdentity, recipientEncPubKeyB64) {
    const packet = Buffer.alloc(PACKET_SIZE);
    let offset = 0;
    packet.writeUInt8(includeIdentity ? 0x01 : 0x00, offset++);

    // Symmetric key + IV
    const symKey = crypto.randomBytes(SYM_KEY_LEN);
    const iv = crypto.randomBytes(IV_LEN);

    // Asymmetric encrypt symKey+IV via recipient's Curve25519 key
    const recipientPub = util.decodeBase64(recipientEncPubKeyB64);
    const shared = nacl.box.before(recipientPub, this.encSecretKey);
    const nonce = crypto.randomBytes(NONCE_LEN);
    const encryptedKey = nacl.box.after(
      Buffer.concat([symKey, iv]),
      nonce,
      shared
    );

    // Ephemeral public key
    const eph = nacl.box.keyPair();
    Buffer.from(eph.publicKey).copy(packet, offset);
    offset += 32;
    Buffer.from(encryptedKey).copy(packet, offset);
    offset += encryptedKey.length;
    Buffer.from(nonce).copy(packet, offset);
    offset += NONCE_LEN;

    // AES-256-GCM encryption
    const cipher = crypto.createCipheriv("aes-256-gcm", symKey, iv);
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    Buffer.from(authTag).copy(packet, offset);
    offset += authTag.length;
    Buffer.from(ciphertext).copy(packet, offset);
    offset += ciphertext.length;

    // Optional include identity public key
    if (includeIdentity) {
      Buffer.from(this.signPublicKey).copy(packet, offset);
      offset += this.signPublicKey.length;
    }

    // Digital signature over data + sender+recipient public keys
    const sigPayload = Buffer.concat([
      data,
      includeIdentity ? this.signPublicKey : Buffer.alloc(0),
      Buffer.from(recipientEncPubKeyB64, "base64"),
    ]);
    const signature = nacl.sign.detached(sigPayload, this.signSecretKey);
    Buffer.from(signature).copy(packet, offset);
    offset += signature.length;

    // Padding
    crypto.randomBytes(PACKET_SIZE - offset - 4).copy(packet, offset);
    offset = PACKET_SIZE - 4;

    // Proof-of-Work nonce
    let powNonce = 0;
    let hash;
    do {
      packet.writeUInt32BE(powNonce++, offset);
      hash = crypto.createHash("sha3-256").update(packet).digest();
    } while (!SecureBroadcastNode._meetsPow(hash));

    return packet;
  }

  _handle(msg) {
    if (msg.length !== PACKET_SIZE) return;
    const hash = crypto.createHash("sha3-256").update(msg).digest();
    if (!SecureBroadcastNode._meetsPow(hash)) return;
    const id = hash.toString("hex");
    if (this.cache.has(id)) return;
    this.cache.set(id, Date.now());
    for (const [k, t] of this.cache) {
      if (Date.now() - t > CACHE_TTL_MS) this.cache.delete(k);
    }

    try {
      let off = 0;
      const flag = msg.readUInt8(off++);
      const ephPub = msg.slice(off, off + 32);
      off += 32;
      const encKeyLen = SYM_KEY_LEN + IV_LEN + nacl.secretbox.overheadLength;
      const encKey = msg.slice(off, off + encKeyLen);
      off += encKeyLen;
      const nonce = msg.slice(off, off + NONCE_LEN);
      off += NONCE_LEN;

      // Decrypt symKey+IV
      const shared = nacl.box.before(ephPub, this.encSecretKey);
      const keyIv = nacl.box.open.after(encKey, nonce, shared);
      if (!keyIv) return;
      const symKey = keyIv.slice(0, SYM_KEY_LEN);
      const iv = keyIv.slice(SYM_KEY_LEN);

      // AES-GCM decrypt
      const authTag = msg.slice(off, off + 16);
      off += 16;
      const encDataEnd =
        msg.length -
        (flag === 0x01 ? this.signPublicKey.length + 64 + 4 : 64 + 4);
      const encData = msg.slice(off, encDataEnd);
      off = encDataEnd;
      const decipher = crypto.createDecipheriv("aes-256-gcm", symKey, iv);
      decipher.setAuthTag(authTag);
      const plain = Buffer.concat([decipher.update(encData), decipher.final()]);

      // Read sender public key if present
      let senderPub = null;
      if (flag === 0x01) {
        senderPub = msg.slice(off, off + 32);
        off += 32;
      }
      const signature = msg.slice(off, off + 64);

      // Verify signature
      if (flag === 0x01) {
        const sigPayload = Buffer.concat([
          plain,
          senderPub,
          Buffer.from(nacl.util.encodeBase64(this.encPublicKey), "base64"),
        ]);
        if (!nacl.sign.detached.verify(sigPayload, signature, senderPub))
          return;
      }

      this.callbacks.forEach((cb) =>
        cb(flag === 0x01 ? util.encodeBase64(senderPub) : null, plain)
      );
    } catch (e) {
      // Ignore malformed packets
    }
  }

  start(port) {
    if (this.running) return;
    this.running = true;
    this.socket.on("message", (msg) => this._handle(msg));
    this.socket.bind(port, () => {
      this._sendLoop();
    });
  }

  _sendLoop() {
    if (!this.running) return;
    setTimeout(() => {
      const data = crypto.randomBytes(200);
      for (const peer of this.peers) {
        const [host, p, pub] = peer.split(":");
        const packet = this._makePacket(data, Math.random() > 0.5, pub);
        this.socket.send(packet, parseInt(p), host);
      }
      this._sendLoop();
    }, (Math.random() * 4 + 1) * 60 * 1000);
  }

  send(data, anon, recipientPub) {
    const packet = this._makePacket(data, !anon, recipientPub);
    for (const peer of this.peers) {
      const [host, p, pub] = peer.split(":");
      if (pub === recipientPub) {
        this.socket.send(packet, parseInt(p), host);
      }
    }
  }

  stop() {
    this.running = false;
    this.socket.close();
  }
}

module.exports = SecureBroadcastNode;
