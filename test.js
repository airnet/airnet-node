airnet = require('./lib/airnet.js');

node = new airnet(3000);
node.start();
node.connect('localhost:3001');
