airnet = require('./lib/airnet.js');

node = new airnet(3000);
node.start();
console.log ("WebSocket created");
