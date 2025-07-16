const MW_SNP_Node = require("./src/MW-SNP-Node");
const os = require("os");

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

const basePort = 5000;
const localIP = getLocalIP();

const nodes = [];

for (let i = 0; i < 3; i++) {
  const port = basePort + i;
  const pkPath = `./keys/test/node${i}_pk.txt`;
  const skPath = `./keys/test/node${i}_sk.txt`;

  // Connections to other two nodes
  const connections = [];
  for (let j = 0; j < 3; j++) {
    if (j !== i) {
      connections.push(`${localIP}:${basePort + j}`);
    }
  }

  const node = new MW_SNP_Node(pkPath, skPath, connections);
  node.onPocket((senderPk, data) => {
    console.log(`Node ${i} received:`, data.toString(), senderPk);
  });
  node.start(port);

  // Send random hello messages to others every 10–20s
  setInterval(() => {
    const msg = `hello from node ${i}`;
    node.send(msg, Math.random() > 0.5);
  }, Math.random() * 10000 + 5000); // 10–20 sec

  nodes.push(node);
}

// Graceful shutdown
process.on("SIGINT", () => {
  nodes.forEach((node) => node.stop());
  process.exit();
});
