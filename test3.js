airnet = require('./index.js');

node = new airnet(3003, {file: "data3.airnet"});
node.start();
node.connect('localhost:3000');
node.connect('54.186.21.235:3000');
