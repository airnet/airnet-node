airnet = require('./index.js');

node = new airnet(3001, {file: "data2.airnet"});
node.start();
node.connect('localhost:3000');