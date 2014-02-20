airnet-node
===========

node.js / npm client for airnet

Usage
==========
Install: `npm install airnet`

Import: `airnet = require('airnet')`

Example:

```
//Create the seed node
seed = new airnet(3000);
seed.start();

peer1 = new airnet(3001,
    {
      autoconnect:false, //If you don't want automatic peer connections
      sqlite: true // If you have included sqlite3 from npm
    }
);

peer1.start();
//Connect to the seed node
peer1.connect('localhost:3000');
```
