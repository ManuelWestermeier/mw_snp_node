const fs = require("fs");
const dgram = require("dgram");
const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const crypto = require("crypto");

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
    if (msg.length !== 1024) return;

    // Verify PoW (first 5 bits of SHA3-256 hash must be 0)
    const hash = crypto.createHash("sha3-256").update(msg).digest();
    if ((hash[0] & 0xf8) !== 0) return;

    // Check if we've already seen this packet
    const id = hash.toString("hex");
    if (this.cache.has(id)) return;
    this.cache.add(id);

    const flag = msg.readUInt8(0);
    const data = msg.slice(1, msg.length - 16); // Truncate potential future footer

    // Currently, senderPk not implemented in decoding logic
    const senderPk = flag === 0x01 ? null : null;

    this.callbacks.forEach((cb) => cb(senderPk, data));
  }

  start(port = 0) {
    if (this.running) return;
    this.running = true;

    this.socket.on("message", (msg, rinfo) => this._handleMessage(msg, rinfo));
    this.socket.bind(port, () => {
      console.log("Node listening on port", this.socket.address().port);
      this._loop(); // Start dummy traffic loop
    });
  }

  _loop() {
    if (!this.running) return;
    const wait = (Math.random() * 4 + 1) * 60 * 1000; // 1–5 min
    setTimeout(async () => {
      await this.send(null, true); // Dummy anonymous packet
      this._loop();
    }, wait);
  }

  async send(data, anonymous = false) {
    const flag = anonymous ? 0x00 : 0x01;
    const packet = Buffer.alloc(1024, 0);

    // Data to fill in (or dummy)
    let payload = data ? Buffer.from(data) : crypto.randomBytes(1023);
    if (payload.length > 1023) {
      throw new Error("Payload too large, must be ≤1023 bytes.");
    }

    packet.writeUInt8(flag, 0);
    payload.copy(packet, 1);

    // PoW: Adjust last 4 bytes (nonce) until first 5 bits of SHA3-256 are 0
    let nonce = 0;
    let hash;
    do {
      packet.writeUInt32BE(nonce++, 1020); // nonce in last 4 bytes
      hash = crypto.createHash("sha3-256").update(packet).digest();
    } while ((hash[0] & 0xf8) !== 0);

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
