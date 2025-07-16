// test-mw_snp_node.js

const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const SecureBroadcastNode = require("./src/MW-SNP-Node.js");

// Hilfsfunktion: Lokale IPv4-Adresse ermitteln
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name in interfaces) {
    for (const iface of interfaces[name]) {
      if (iface.family === "IPv4" && !iface.internal) {
        return iface.address;
      }
    }
  }
  return "127.0.0.1";
}

const localIP = getLocalIP();
const basePort = 5000;
const nodeCount = 5;
const keyDirRoot = path.join(__dirname, "keys", "test");
fs.mkdirSync(keyDirRoot, { recursive: true });

// Schritt 1: Nodes erstellen und Schlüssel laden/generieren
const nodes = [];
const allPubKeys = [];

for (let i = 0; i < nodeCount; i++) {
  const dir = path.join(keyDirRoot, `node${i}`);
  fs.mkdirSync(dir, { recursive: true });

  // Pfade für public/secret Ed25519 key
  const pkPath = path.join(dir, "keypair_pk.txt");
  const skPath = path.join(dir, "keypair_sk.txt");
  const node = new SecureBroadcastNode(dir, []);
  nodes.push(node);

  // Public‑Key lesen
  const keyB64 = fs.readFileSync(pkPath, "utf8").trim();
  allPubKeys.push(keyB64);
}

// Hilfsfunktion: zufällige Peers-Strings erzeugen
function getRandomPeers(index, count = 2) {
  const others = Array.from({ length: nodeCount }, (_, j) => j).filter(
    (j) => j !== index
  );
  for (let i = others.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [others[i], others[j]] = [others[j], others[i]];
  }
  return others
    .slice(0, count)
    .map((j) => `${localIP}:${basePort + j}:${allPubKeys[j]}`);
}

// Schritt 2: Peers verteilen
nodes.forEach((node, idx) => {
  node.peers = getRandomPeers(idx);
});

// Schritt 3: Start und Empfangs-Callback
nodes.forEach((node, idx) => {
  const port = basePort + idx;
  node.onMessage((senderPk, data) => {
    const text = data.toString("utf8").replace(/[^\w \.,_-]/g, "");
    console.log(
      `Node ${idx} erhalten: "${text}"`,
      senderPk ? "(signed)" : "(anon)"
    );
  });
  node.start(port);
  console.log(`Node ${idx} gestartet auf Port ${port}`);
});

// Schritt 4: Periodisches Senden zufälliger Nachrichten (1 Sekunde)
setInterval(() => {
  const i = Math.floor(Math.random() * nodes.length);
  const node = nodes[i];
  if (!node.peers.length) return;

  const [host, portStr, recipientPk] =
    node.peers[Math.floor(Math.random() * node.peers.length)].split(":");

  const msgLen = Math.floor(Math.random() * 10) + 10;
  const payload =
    `Node${i}: ` +
    crypto.randomBytes(msgLen).toString("base64").slice(0, msgLen);
  const anon = Math.random() > 0.5;

  node.send(Buffer.from(payload, "utf8"), anon, recipientPk);
  console.log(
    `Node ${i} sendet ${anon ? "anonym" : "signiert"} → ${host}:${portStr}`
  );
}, 1000);

// Graceful Shutdown
process.on("SIGINT", () => {
  console.log("Beende alle Nodes...");
  nodes.forEach((n) => n.stop());
  process.exit();
});
