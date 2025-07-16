// test-nodes-echo.js
// Fünf Nodes: 0=Echo-Node, 1=Client, 2-4=Idle
// Node 0: sendet empfangene (nicht-anonyme) Nachrichten zurück an den Sender
// Node 1: sendet alle 3 Sekunden Nachrichten an Node 0
// Alle Nodes loggen eingegangene Nachrichten

const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const util = require('tweetnacl-util');
const MW_SNP_Node = require('./src/MW-SNP-Node.js');

// Hilfsfunktion: Lokale IPv4-Adresse ermitteln
function getLocalIP() {
  const ifs = os.networkInterfaces();
  for (const name in ifs) {
    for (const iface of ifs[name]) {
      if (iface.family === 'IPv4' && !iface.internal) return iface.address;
    }
  }
  return '127.0.0.1';
}

const localIP = getLocalIP();
const basePort = 6000;
const nodeCount = 5;
const keyRoot = path.join(__dirname, 'keys', 'echo_test');
fs.mkdirSync(keyRoot, { recursive: true });

// Erzeuge Nodes und Public + Encryption Keys aus Instanzen
const nodes = [];
const pubKeys = [];
for (let i = 0; i < nodeCount; i++) {
  const dir = path.join(keyRoot, `node${i}`);
  fs.mkdirSync(dir, { recursive: true });

  // Pfade für Ed25519 keypair (sign) und Encryption-Key abgeleitet
  const pkPath = path.join(dir, 'keypair_pk.txt');
  const skPath = path.join(dir, 'keypair_sk.txt');
  const node = new MW_SNP_Node(pkPath, skPath, []);
  nodes.push(node);

  // Encryption Public Key (Curve25519) aus node.encPublicKey
  pubKeys[i] = util.encodeBase64(node.encPublicKey);
}

// Konfiguriere Peers
nodes.forEach((node, idx) => {
  if (idx === 1) {
    // Client sendet an Echo (Node 0)
    node.connections = [`${localIP}:${basePort}:${pubKeys[0]}`];
  } else if (idx === 0) {
    // Echo sendet zurück an Client (Node 1)
    node.connections = [`${localIP}:${basePort + 1}:${pubKeys[1]}`];
  } else {
    // Idle-Nodes ohne Peers
    node.connections = [];
  }
});

// Logging für alle Nodes
nodes.forEach((node, idx) => {
  node.onMessage((sender, data) => {
    console.log(`Node${idx} received from ${sender || 'anon'}: ${data.toString()}`);
  });
});

// Start aller Nodes
nodes.forEach((node, idx) => node.start(basePort + idx));
console.log('Echo network läuft: Node0=Echo (6000), Node1=Client (6001), Node2-4 idle');

// Client (Node1): schickt alle 3s eine Nachricht an Echo
setInterval(() => {
  const msg = `ping ${new Date().toISOString()}`;
  nodes[1].send(Buffer.from(msg), false, pubKeys[0]);
  console.log(`Client sent: ${msg}`);
}, 3000);

// Echo-Node (Node0): schickt empfangene nicht-anonyme Nachrichten zurück
nodes[0].onMessage((sender, data) => {
  if (!sender) return;  // nur wenn signiert
  const reply = Buffer.from(`echo: ${data.toString()}`);
  nodes[0].send(reply, false, sender);
  console.log(`Echoed back to ${sender}: ${data.toString()}`);
});

// Sauberes Beenden
process.on('SIGINT', () => {
  console.log('Beende Echo network...');
  nodes.forEach(n => n.stop());
  process.exit();
});
