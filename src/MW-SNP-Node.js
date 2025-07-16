// Secure Broadcast Node Implementation
// Implements: fixed 1024-byte packets, PoW, AES-256-GCM, Curve25519 key exchange, Ed25519 signatures,
// replay protection, dummy traffic, gossip-based broadcast.

const fs = require("fs");
const os = require("os");
const dgram = require("dgram");
const crypto = require("crypto");
const nacl = require("tweetnacl");
const util = require("tweetnacl-util");

// Constants
const PACKET_SIZE = 1024;
const POW_LEADING_ZERO_BITS = 5;
const SYM_KEY_LEN = 32; // AES-256 key
const IV_LEN = 12; // AES-GCM standard
const NONCE_LEN = 24; // for NaCl box
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 min cache TTL

class SecureBroadcastNode {
  constructor(keyDir, peers = []) {
    this.peers = peers; // array of "host:port:pubKeyBase64"
    this.socket = dgram.createSocket("udp4");
    this.cache = new Map(); // id -> timestamp
    this.callbacks = [];
    this.running = false;
    this.keyDir = keyDir;

    this._loadOrGenerateKeys();
  }

  _loadOrGenerateKeys() {
    const sigPk = `${this.keyDir}/sign_pk.txt`,
      sigSk = `${this.keyDir}/sign_sk.txt`;
    const encPk = `${this.keyDir}/enc_pk.txt`,
      encSk = `${this.keyDir}/enc_sk.txt`;
    fs.mkdirSync(this.keyDir, { recursive: true });

    // Signing keys (Ed25519)
    if (fs.existsSync(sigPk) && fs.existsSync(sigSk)) {
      this.signPublicKey = util.decodeBase64(fs.readFileSync(sigPk, "utf8"));
      this.signSecretKey = util.decodeBase64(fs.readFileSync(sigSk, "utf8"));
    } else {
      const kp = nacl.sign.keyPair();
      this.signPublicKey = kp.publicKey;
      this.signSecretKey = kp.secretKey;
      fs.writeFileSync(sigPk, util.encodeBase64(this.signPublicKey));
      fs.writeFileSync(sigSk, util.encodeBase64(this.signSecretKey));
    }

    // Encryption keys (X25519)
    if (fs.existsSync(encPk) && fs.existsSync(encSk)) {
      this.encPublicKey = util.decodeBase64(fs.readFileSync(encPk, "utf8"));
      this.encSecretKey = util.decodeBase64(fs.readFileSync(encSk, "utf8"));
    } else {
      const kp = nacl.box.keyPair();
      this.encPublicKey = kp.publicKey;
      this.encSecretKey = kp.secretKey;
      fs.writeFileSync(encPk, util.encodeBase64(this.encPublicKey));
      fs.writeFileSync(encSk, util.encodeBase64(this.encSecretKey));
    }
  }

  onMessage(fn) {
    this.callbacks.push(fn);
  }

  _makePacket(dataBuffer, includeIdentity, recipientPubKey) {
    const packet = Buffer.alloc(PACKET_SIZE);
    let offset = 0;

    // 1. Flag
    packet.writeUInt8(includeIdentity ? 0x01 : 0x00, offset++);

    // 2. Generate symmetric key + IV
    const symKey = crypto.randomBytes(SYM_KEY_LEN);
    const iv = crypto.randomBytes(IV_LEN);

    // Asymmetric encrypt symKey+IV via recipient X25519
    const shared = nacl.box.before(
      util.decodeBase64(recipientPubKey),
      this.encSecretKey
    );
    const nonce = crypto.randomBytes(NONCE_LEN);
    const encryptedKey = nacl.box.after(
      Buffer.concat([symKey, iv]),
      nonce,
      shared
    );

    // Copy ephemeral public key, encryptedKey, nonce
    const eph = nacl.box.keyPair();
    Buffer.from(eph.publicKey).copy(packet, offset);
    offset += 32;
    Buffer.from(encryptedKey).copy(packet, offset);
    offset += encryptedKey.length;
    Buffer.from(nonce).copy(packet, offset);
    offset += NONCE_LEN;

    // 3. Encrypted data via AES-256-GCM
    const cipher = crypto.createCipheriv("aes-256-gcm", symKey, iv);
    const encData = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    Buffer.from(authTag).copy(packet, offset);
    offset += authTag.length;
    Buffer.from(encData).copy(packet, offset);
    offset += encData.length;

    // 4. Optional identity
    if (includeIdentity) {
      Buffer.from(this.signPublicKey).copy(packet, offset);
      offset += 32;
    }

    // 5. Signature
    const sigPayload = Buffer.concat([
      dataBuffer,
      includeIdentity ? this.signPublicKey : Buffer.alloc(0),
      Buffer.from(recipientPubKey, "base64"),
    ]);
    const signature = nacl.sign.detached(sigPayload, this.signSecretKey);
    Buffer.from(signature).copy(packet, offset);
    offset += signature.length;

    // rest is random padding
    crypto.randomBytes(PACKET_SIZE - offset).copy(packet, offset);

    // 6. Compute PoW and append 4-byte nonce at end
    let powNonce = 0;
    const powOffset = PACKET_SIZE - 4;
    let hash;
    do {
      packet.writeUInt32BE(powNonce++, powOffset);
      hash = crypto.createHash("sha3-256").update(packet).digest();
    } while (!SecureBroadcastNode._meetsPow(hash));

    return packet;
  }

  static _meetsPow(hash) {
    // require POW_LEADING_ZERO_BITS zeros
    const mask = 0xff << (8 - POW_LEADING_ZERO_BITS);
    return (hash[0] & mask) === 0;
  }

  _handle(msg) {
    if (msg.length !== PACKET_SIZE) return;
    const hash = crypto.createHash("sha3-256").update(msg).digest();
    if (!SecureBroadcastNode._meetsPow(hash)) return;
    const id = hash.toString("hex");
    if (this.cache.has(id)) return;
    this.cache.set(id, Date.now());

    // expire old
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

      const shared = nacl.box.before(ephPub, this.encSecretKey);
      const keyIv = nacl.box.open.after(encKey, nonce, shared);
      if (!keyIv) return;
      const symKey = keyIv.slice(0, SYM_KEY_LEN);
      const iv = keyIv.slice(SYM_KEY_LEN);

      const authTag = msg.slice(off, off + 16);
      off += 16;
      const encData = msg.slice(off, PACKET_SIZE - 32 - 4); // reserve 32 sig + 4 nonce
      off = PACKET_SIZE - 32 - 4;

      // decrypt
      const decipher = crypto.createDecipheriv("aes-256-gcm", symKey, iv);
      decipher.setAuthTag(authTag);
      const plain = Buffer.concat([decipher.update(encData), decipher.final()]);

      // read signature
      const senderPub = flag === 0x01 ? msg.slice(off, off + 32) : null;
      off += flag === 0x01 ? 32 : 0;
      const sig = msg.slice(off, off + 64);

      // verify
      if (flag === 0x01) {
        const sigPayload = Buffer.concat([
          plain,
          senderPub,
          Buffer.from(nacl.util.encodeBase64(this.encPublicKey), "base64"),
        ]);
        if (!nacl.sign.detached.verify(sigPayload, sig, senderPub)) return;
      }

      this.callbacks.forEach((cb) =>
        cb(flag === 0x01 ? util.encodeBase64(senderPub) : null, plain)
      );
    } catch (e) {
      // ignore
    }
  }

  start(port) {
    if (this.running) return;
    this.running = true;
    this.socket.on("message", (msg, rinfo) => this._handle(msg));
    this.socket.bind(port, () => {
      console.log("Node listening on", port);
      this._sendLoop();
    });
  }

  _sendLoop() {
    if (!this.running) return;
    setTimeout(() => {
      // pick message or dummy
      const data = crypto.randomBytes(200);
      for (const peer of this.peers) {
        const [host, port, pub] = peer.split(":");
        const packet = this._makePacket(data, Math.random() > 0.5, pub);
        this.socket.send(packet, parseInt(port), host);
      }
      this._sendLoop();
    }, (Math.random() * 4 + 1) * 60 * 1000);
  }

  stop() {
    this.running = false;
    this.socket.close();
  }
}

module.exports = SecureBroadcastNode;
