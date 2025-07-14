# Secure Cryptographic Broadcast Network

A decentralized, anonymous, and secure broadcast network designed to resist traffic analysis, spam, and replay attacks using fixed-size encrypted packets, dummy traffic, and cryptographic guarantees.

## Features

- 🔐 End-to-end encryption with AES-GCM / ChaCha20
- 🧾 Optional sender authentication via Ed25519 signatures
- 🧊 Fixed-size 1024-byte packets
- 💬 Periodic dummy message broadcast
- 🛡️ Spam protection via Proof of Work
- 🔄 Replay attack prevention using packet hash cache
- 🧩 Gossip-based routing for scalability
- 🧅 Obfuscated timing and metadata

---

## Packet Format

Each 1024-byte packet contains:

- Sender Info Flag (0x01 for signed, 0x00 for anonymous)
- Encrypted AES Key + IV
- Encrypted recipient public key hash
- Encrypted payload data
- Optional sender public key and digital signature
- Padding
- Hashcash-style Proof of Work

---

## Requirements

- Node.js v18+
- RSA/ECC and AES crypto libraries (native or `crypto` module)
- Public & Private key files

---

## Start Instructions

To run a node in the network:

```bash
node ./run.js keys/pk.txt keys/sk.txt <HOST>:<PORT> [<PEER_HOST:PORT>...]
```

### Example

Start your node on port 7722 and connect to a peer on 7723:

```bash
node ./run.js keys/pk.txt keys/sk.txt localhost:7722 localhost:7723
```

### Arguments

- `keys/pk.txt`: Your **public key** file
- `keys/sk.txt`: Your **private key** file
- `<HOST>:<PORT>`: Address and port this node listens on
- `[...PEERS]`: List of initial peer nodes to connect to

---

## Notes

- Each node sends a 1024-byte packet every 1–5 minutes.
- When there's no real data, the node sends random dummy packets.
- All packets include a proof-of-work challenge (e.g., 5 leading zero bits in hash).
- Replay protection is implemented via recent packet hash cache.

---

## Security

- Asymmetric Encryption: RSA-4096 / Curve25519
- Symmetric Encryption: AES-256-GCM / ChaCha20-Poly1305
- Signatures: Ed25519 / ECDSA
- Hashes: SHA3-256 / BLAKE2b
- PoW: Hashcash-style with target difficulty

---

## License

MIT (or add your license here)
