const MW_SNP_Node = require('./src/MW_SNP_Node');
const [, , pkPath, skPath, ...conns] = process.argv;

const node = new MW_SNP_Node(pkPath, skPath, conns);

node.onPocket((senderPk, data) => {
  console.log('Received:', data.toString() + "from" + senderPk);
});

node.start();

process.on('SIGINT', () => {
  node.stop();
  process.exit();
});
