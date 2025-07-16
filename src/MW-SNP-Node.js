const fs = require("fs");
const dgram = require("dgram");
const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const crypto = require("crypto");

const PACKET_SIZE = 1024;
const POW_DIFFICULTY = 0xf8; // first 5 bits must be zero
const SIGNATURE_SIZE = 64;
const PUBKEY_SIZE = 32;

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
      const keypair = nacl.sign.keyPair();
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
    if ((hash[0] & POW_DIFFICULTY) !== 0) return;

    const id = hash.toString("hex");
    if (this.cache.has(id)) return;
    this.cache.add(id);

    const flag = msg.readUInt8(0);
    let senderPk = null;
    let data;

    if (flag === 0x01) {
      const sig = msg.slice(1, 1 + SIGNATURE_SIZE);
      const pk = msg.slice(
        1 + SIGNATURE_SIZE,
        1 + SIGNATURE_SIZE + PUBKEY_SIZE
      );
      const payload = msg.slice(
        1 + SIGNATURE_SIZE + PUBKEY_SIZE,
        PACKET_SIZE - 4
      );

      const valid = nacl.sign.detached.verify(payload, sig, pk);
      if (!valid) return;

      senderPk = util.encodeBase64(pk);
      data = payload;
    } else {
      data = msg.slice(1, PACKET_SIZE - 4);
    }

    this.callbacks.forEach((cb) => cb(senderPk, data));
  }

  start(port = 0) {
    if (this.running) return;
    this.running = true;
    this.socket.on("message", (msg, rinfo) => this._handleMessage(msg, rinfo));
    this.socket.bind(port, () => {
      console.log("Node listening on port", this.socket.address().port);
      this._loop();
    });
  }

  _loop() {
    if (!this.running) return;
    const wait = (Math.random() * 4 + 1) * 60 * 1000;
    setTimeout(async () => {
      await this.send(null, true);
      this._loop();
    }, wait);
  }

  async send(data, anonymous = false) {
    const flag = anonymous ? 0x00 : 0x01;
    const packet = Buffer.alloc(PACKET_SIZE, 0);
    packet.writeUInt8(flag, 0);

    let payload;
    if (!data) {
      payload = crypto.randomBytes(PACKET_SIZE - 1 - 4);
    } else {
      payload = Buffer.from(data);
    }

    if (!anonymous) {
      const sig = nacl.sign.detached(payload, this.secretKey);
      Buffer.from(sig).copy(packet, 1);
      Buffer.from(this.publicKey).copy(packet, 1 + SIGNATURE_SIZE);
      payload.copy(packet, 1 + SIGNATURE_SIZE + PUBKEY_SIZE);
    } else {
      payload.copy(packet, 1);
    }

    let nonce = 0;
    let hash;
    do {
      packet.writeUInt32BE(nonce++, PACKET_SIZE - 4);
      hash = crypto.createHash("sha3-256").update(packet).digest();
    } while ((hash[0] & POW_DIFFICULTY) !== 0);

    for (const conn of this.connections) {
      const [host, portStr] = conn.split(":");
      const port = parseInt(portStr, 10);
      this.socket.send(packet, port, host, (err) => {
        if (err) console.error("Send error:", err.message);
      });
    }
  }

  stop() {
    if (!this.running) return;
    this.running = false;
    this.socket.close(() => {
      console.log("Node stopped.");
    });
  }
}

module.exports = MW_SNP_Node;
