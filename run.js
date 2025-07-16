const MW_SNP_Node = require("./src/MW-SNP-Node");
const [, , pkPath, skPath, ...conns] = process.argv;

const node = new MW_SNP_Node(pkPath, skPath, conns);

node.onPocket((senderPk, data) => {
  console.log("Received:", data.toString() + "from" + senderPk);
});

node.start(7222);

process.on("SIGINT", () => {
  node.stop();
  process.exit();
});
