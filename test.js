airnet = require('./index.js');

node = new airnet(3000);
node.start();
//node.connect('localhost:3001');

//secondnode = new airnet(3001, {file: "data2.airnet"});
//secondnode.start();
//secondnode.connect('localhost:3000');
