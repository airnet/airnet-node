airnet = require('./index.js');

node = new airnet(3001, {file: "data2.airnet", ip: "54.186.25.188"});
node.start();
node.connect('localhost:3000');
node.connect('172.31.15.243:3000');
