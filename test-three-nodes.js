const MW_SNP_Node = require("./src/MW-SNP-Node.js");
const os = require("os");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

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
const nodeCount = 5; // für Test kleiner
const keyDir = path.join(__dirname, "keys/test");
fs.mkdirSync(keyDir, { recursive: true });

// Schritt 1: Erzeuge Nodes nur mit Pfaden, lade oder generiere Keys
const nodes = [];
const allPublicKeys = [];

// Erstmal nur Nodes anlegen, damit Keys da sind
for (let i = 0; i < nodeCount; i++) {
  const pkPath = path.join(keyDir, `node${i}_pk.txt`);
  const skPath = path.join(keyDir, `node${i}_sk.txt`);
  const node = new MW_SNP_Node(pkPath, skPath, []);
  allPublicKeys[i] = fs.readFileSync(pkPath, "utf8").trim();
  nodes.push(node);
}

// Hilfsfunktion: Peers (host:port:publicKey)
function getRandomPeers(myIndex, count = 2) {
  const others = Array.from({ length: nodeCount }, (_, i) => i).filter(
    (i) => i !== myIndex
  );
  for (let i = others.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [others[i], others[j]] = [others[j], others[i]];
  }
  return others
    .slice(0, count)
    .map((j) => `${localIP}:${basePort + j}:${allPublicKeys[j]}`);
}

// Schritt 2: Setze Verbindungen mit Public Keys
for (let i = 0; i < nodeCount; i++) {
  nodes[i].connections = getRandomPeers(i);
}

// Schritt 3: Starte alle Nodes
for (let i = 0; i < nodeCount; i++) {
  const port = basePort + i;
  nodes[i].onPocket((senderPk, data) => {
    const text = data.toString("utf8").replace(/[^a-zA-Z0-9 .,_-]/g, "");
    console.log(
      `Node ${i} received: "${text}" ${senderPk ? "(signed)" : "(anon)"}`
    );
  });
  nodes[i].start(port);
}

// Schritt 4: Sendet Nachrichten an zufällige Peers aus der Verbindungs-Liste
for (let i = 0; i < nodeCount; i++) {
  setInterval(() => {
    if (nodes[i].connections.length === 0) return;
    // Wähle zufälligen Empfänger aus Verbindungen
    const target =
      nodes[i].connections[
        Math.floor(Math.random() * nodes[i].connections.length)
      ];
    const [host, port, recipientPk] = target.split(":");
    const msgLength = Math.floor(Math.random() * 10) + 10;
    const msg =
      `Node${i} message: ` +
      crypto.randomBytes(msgLength).toString("base64").slice(0, msgLength);

    const anonymous = Math.random() > 0.4;
    nodes[i].send(Buffer.from(msg, "utf8"), anonymous, recipientPk);
  }, Math.random() * 10000 + 5000);
}

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("Shutting down...");
  nodes.forEach((node) => node.stop());
  process.exit();
});
