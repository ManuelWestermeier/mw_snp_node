const fs = require("fs");
const dgram = require("dgram");
const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const crypto = require("crypto");

const PACKET_SIZE = 1024;
const POW_TARGET = 0xf8; // first 5 bits must be 0
const SYM_KEY_SIZE = 32;
const NONCE_SIZE = 24;

class MW_SNP_Node {
  constructor(pkPath, skPath, connections = []) {
    this.pkPath = pkPath;
    this.skPath = skPath;
    this.connections = connections;
    this.socket = dgram.createSocket("udp4");
    this.callbacks = [];
    this.cache = new Set();
    this.running = false;
    this._loadOrGenerateKeys();
  }

  _loadOrGenerateKeys() {
    if (fs.existsSync(this.pkPath) && fs.existsSync(this.skPath)) {
      this.publicKey = util.decodeBase64(fs.readFileSync(this.pkPath, "utf8"));
      this.secretKey = util.decodeBase64(fs.readFileSync(this.skPath, "utf8"));
    } else {
      const keypair = nacl.box.keyPair();
      this.publicKey = keypair.publicKey;
      this.secretKey = keypair.secretKey;
      fs.writeFileSync(this.pkPath, util.encodeBase64(this.publicKey));
      fs.writeFileSync(this.skPath, util.encodeBase64(this.secretKey));
    }
  }

  onPocket(fn) {
    this.callbacks.push(fn);
    return this;
  }

  _handleMessage(msg, rinfo) {
    if (msg.length !== PACKET_SIZE) return;
    const hash = crypto.createHash("sha3-256").update(msg).digest();
    if ((hash[0] & POW_TARGET) !== 0) return;
    const id = hash.toString("hex");
    if (this.cache.has(id)) return;
    this.cache.add(id);

    const flag = msg.readUInt8(0);
    let offset = 1;

    try {
      const ephPub = msg.slice(offset, offset + 32);
      offset += 32;

      const encSymKey = msg.slice(offset, offset + 80); // box encrypted
      offset += 80;

      const nonce = msg.slice(offset, offset + NONCE_SIZE);
      offset += NONCE_SIZE;

      const encPayload = msg.slice(offset, PACKET_SIZE - 4);
      const powNonce = msg.readUInt32BE(PACKET_SIZE - 4);

      const sharedSecret = nacl.box.before(ephPub, this.secretKey);
      const symKey = nacl.box.open.after(encSymKey, nonce, sharedSecret);
      if (!symKey) return;

      const plain = nacl.secretbox.open(encPayload, nonce, symKey);
      if (!plain) return;

      const data = Buffer.from(plain);
      const senderPk = flag === 0x01 ? ephPub.toString("base64") : null;
      this.callbacks.forEach((cb) => cb(senderPk, data));
    } catch (err) {
      return;
    }
  }

  start(port = 0) {
    if (this.running) return;
    this.running = true;
    this.socket.on("message", (msg, rinfo) => this._handleMessage(msg, rinfo));
    this.socket.bind(port, () => {
      console.log("Listening on", this.socket.address().port);
      this._loop();
    });
  }

  _loop() {
    if (!this.running) return;
    const wait = (Math.random() * 4 + 1) * 60000;
    setTimeout(() => {
      const randData = crypto.randomBytes(200);
      this.connections.forEach((c) => {
        const [host, port, pkb64] = c.split(":");
        if (pkb64) {
          this.send(randData, true, pkb64);
        }
      });
      this._loop();
    }, wait);
  }

  async send(data, anonymous = false, recipientPkBase64 = null) {
    const packet = Buffer.alloc(PACKET_SIZE, 0);
    const flag = anonymous ? 0x00 : 0x01;
    packet.writeUInt8(flag, 0);

    if (!recipientPkBase64) {
      console.error("Recipient public key required.");
      return;
    }

    const recipientPk = util.decodeBase64(recipientPkBase64);
    const ephKeypair = nacl.box.keyPair();
    const sharedSecret = nacl.box.before(recipientPk, ephKeypair.secretKey);

    const symKey = crypto.randomBytes(SYM_KEY_SIZE);
    const nonce = crypto.randomBytes(NONCE_SIZE);
    const encryptedSymKey = nacl.box.after(symKey, nonce, sharedSecret);

    const encPayload = nacl.secretbox(data, nonce, symKey);

    let offset = 1;
    Buffer.from(ephKeypair.publicKey).copy(packet, offset);
    offset += 32;
    Buffer.from(encryptedSymKey).copy(packet, offset);
    offset += encryptedSymKey.length;
    Buffer.from(nonce).copy(packet, offset);
    offset += nonce.length;
    Buffer.from(encPayload).copy(packet, offset);
    offset = PACKET_SIZE - 4;

    // Proof of work
    let powNonce = 0;
    let hash;
    do {
      packet.writeUInt32BE(powNonce++, offset);
      hash = crypto.createHash("sha3-256").update(packet).digest();
    } while ((hash[0] & POW_TARGET) !== 0);

    // Send
    for (const conn of this.connections) {
      const [host, portStr, pk] = conn.split(":");
      if (pk !== recipientPkBase64) continue;
      const port = parseInt(portStr);
      this.socket.send(packet, port, host);
    }
  }

  stop() {
    if (!this.running) return;
    this.running = false;
    this.socket.close(() => {
      console.log("Stopped");
    });
  }
}

module.exports = MW_SNP_Node;
