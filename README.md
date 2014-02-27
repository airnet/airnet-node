![airnet-node](http://i.imgur.com/egTSDXq.png)
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
      usefile: true,
      file: "Save.airnet"
    }
);

peer1.start();
//Connect to the seed node
peer1.connect('localhost:3000');
```
