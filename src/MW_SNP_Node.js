const fs = require('fs');
const dgram = require('dgram');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');

class MW_SNP_Node {
  constructor(pkPath, skPath, connections=[]) {
    this.pkPath = pkPath;
    this.skPath = skPath;
    this.connections = connections;
    this.socket = dgram.createSocket('udp4');
    this.callbacks = [];
    this.cache = new Set();
    this.running = false;
    this._loadOrGenerateKeys();
  }

  _loadOrGenerateKeys() {
    if (fs.existsSync(this.pkPath) && fs.existsSync(this.skPath)) {
      this.publicKey = util.decodeBase64(fs.readFileSync(this.pkPath, 'utf8'));
      this.secretKey = util.decodeBase64(fs.readFileSync(this.skPath, 'utf8'));
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
    // Verify PoW and cache
    const hash = require('crypto').createHash('sha3-256').update(msg).digest();
    if (hash.readUInt8(0) & 0xF8) return; // first 5 bits must be zero
    const id = hash.toString('hex');
    if (this.cache.has(id)) return;
    this.cache.add(id);
    // Extract payload flag and data (skip parsing for brevity)
    const flag = msg.readUInt8(0);
    const data = msg.slice(1, msg.length - 16);
    this.callbacks.forEach(cb => cb(null, data));
  }

  start(port=0) {
    if (this.running) return;
    this.running = true;
    this.socket.on('message', (msg, rinfo) => this._handleMessage(msg, rinfo));
    this.socket.bind(port, () => {
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

  async send(data, anonymous=false) {
    // Prepare packet
    const flag = anonymous ? 0x00 : 0x01;
    let payload = data ? Buffer.from(data) : crypto.randomBytes(1000);
    const packet = Buffer.alloc(1024, 0);
    packet.writeUInt8(flag, 0);
    payload.copy(packet, 1);
    // PoW
    const hashFn = require('crypto').createHash;
    let hash;
    let nonce = 0;
    do {
      packet.writeUInt32BE(nonce++, 1020);
      hash = hashFn('sha3-256').update(packet).digest();
    } while (hash.readUInt8(0) & 0xF8);
    // Send
    for (const conn of this.connections) {
      const [host, port] = conn.split(':');
      this.socket.send(packet, port, host);
    }
  }

  stop() {
    this.running = false;
    this.socket.close();
  }
}

module.exports = MW_SNP_Node;
