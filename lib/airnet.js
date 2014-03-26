var util = require('util');
var crypto = require('crypto');
var http = require('http');
var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;
var Fiber = require('fibers');
var ProtoBuf = require('protobufjs');
var pbuilder = ProtoBuf.loadProtoFile("./airnet/proto/airnet.proto");
var path = require('path'),
    appDir = path.dirname(require.main.filename);
var sbuilder = ProtoBuf.loadProtoFile('./lib/data.proto');
var fs = require('fs');
var ursa = require('ursa');
var _ = require("underscore");

//Message types
var speer = sbuilder.build("peer");
var ssave = sbuilder.build("save");

//Network message types
var CONNECT_NEWCLIENT = pbuilder.build("CONNECT_NEWCLIENT");
var CONNECT_UNKNOWN = pbuilder.build("CONNECT_UNKNOWN");
var GOSSIP_NEWCLIENT = pbuilder.build("GOSSIP_NEWCLIENT");
var TIMESTAMP = pbuilder.build("TIMESTAMP");
var CONNECT_INIT = pbuilder.build("CONNECT_INIT");
var GOSSIP_MESSAGE = pbuilder.build("GOSSIP_MESSAGE");
var INVALID_ID = pbuilder.build("INVALID_ID");
var CONNECT_ACCEPT = pbuilder.build("CONNECT_ACCEPT");
var GOSSIP_PEERS = pbuilder.build("GOSSIP_PEERS");
var INVALID_TIME = pbuilder.build("INVALID_TIME");


function sleep(ms) {
  var fiber = Fiber.current;
  setTimeout(function() {
    fiber.run();
  }, ms);
  Fiber.yield();
}

var getHashSum = function() {
  return crypto.createHash('sha256');
};

var genTimestamp = function() {
  return new TIMESTAMP({time: new Date().getTime()});
}

var Airnet = function(port, config)
{
  var state = 0;
  //Each peer is represented as key: id
  var _this = this;
  this.peers = [];
  this.wss = null;
  this.clientinfo = {};
  this.port = port;
  this.connectqueue = [];
  //Global index of nodes
  this.nodeidx = {};
  this.stop = false;

  this.config = {
    autoconnect:
      true,
    usefile:
      true,
    file:
      appDir+'/data.airnet',
    ip:
      ""
  };

  this.peersToTry = [];

  if (config != null) {
    var k;
    for(k in config) {
      v = config[k];
      if(this.config[k] != undefined)
        this.config[k] = v;
    }
  }

  this.protocol = {
    invalid_id:
      function(peer, msg) {
        var msg = new INVALID_ID({invalid:msg});
        _this.sendMessage(peer.ws, {invalidid: msg});
      },
    invalid_sig:
      function(peer, msg) {
        var msg = new INVALID_HASH({invalid: msg});
        _this.sendMessage(peer.ws, {invalidhash: msg});
      },
    invalid_time:
      function(peer, msg) {
        var msg = new INVALID_TIME({invalid: msg, remotetime: msg.time});
        _this.sendMessage(peer.ws, {invalidtime: msg});
      },
    connect_init:
      function(peer) {
        var msg = new CONNECT_INIT({
          id: _this.id,
          ip: _this.publicaddr
        });
        _this.sendMessage(peer.ws, {connectinit: msg});
      },
    connect_newclient:
      function(peer) {
        var msg = new CONNECT_NEWCLIENT({
          id: _this.id,
        pkey: _this.pubkey.toPublicPem().toString(),
        info: JSON.stringify(_this.clientinfo),
        infohash: _this.privkey.hashAndSign("sha256", JSON.stringify(_this.clientinfo))
        });
        _this.sendMessage(peer.ws, {connectnc: msg});
      },
    connect_accept:
      function(peer, msg) {
        var msg = new CONNECT_ACCEPT({
          id: _this.id
        });
        _this.sendMessage(peer.ws, {connectaccept: msg});
      },
    gossip_peers: 
      function(peer, msg){
        var data = {
          ips: []
        }
        for(var i=0;i<_this.peers.length;i++){
          var peer = _this.peers[i];
          data.ips.push(peer.ip);
        }
        _this.sendMessage(peer.ws, {peerlist: new GOSSIP_PEERS(data)});
      }
  };

  //todo:
  //   - implement invalid_sig
  //   - implement invalid_time
  //   - implement gossip_rmnode
  this.protocolr = {
    connect_unknown: function(peer, msg) {
      var data = msg.connectunknown;
      if(data.moreinfo) {
        console.log(' - sending more info to peer');
        _this.protocol.connect_newclient(peer);
      }
    },
    gossip_peers: function(peer,msg){
      var ips = msg.peerlist.ips;
      for(var i=0;i<ips.length;i++){
        _this.peersToTry.push(ips[i]);
      }
    },
    gossip_newclient: function(peer, msg){
      var data = msg.newclient;
      if(data.id === this.id) return;

      var nnode = {
        id: data.id,
        pkey: data.pkey,
        info: data.info,
        infohash: data.infohash
      };
      
      //Verify info hash
      var pkey = nnode.pkey;
      var info = nnode.info;
      var infohash = nnode.infohash;
      var ukey = ursa.coercePublicKey(pkey);
      if(!ukey.hashAndVerify("sha256", info, infohash.toBuffer(), "utf8")){
        console.log(' ! gossiped peer does not verify, ignored');
        return;
      }

      //Verify ID
      if(_this.hashKey(pkey) != nnode.id){
        console.log(" ! gossiped peer ID not valid, ignored");
        return;
      }

      //Add to network
      _this.nodeidx[nnode.id] = nnode;
      console.log(" - new gossiped peer received");
      console.log("   -> ID = "+nnode.id);
      
      if(msg.retrans){
        this.transmitnode(nnode);
      }
    },
    connect_newclient: function(peer, msg) {
      var data = msg.connectnc;
      //verify hash
      var pkey = data.pkey;
      var info = data.info;
      var infohash = data.infohash;
      var cpkey = ursa.coercePublicKey(pkey);

      var valid = cpkey.hashAndVerify("sha256", info, infohash.toBuffer(), "utf8");

      if(!valid) {
        console.log('   -> peer signature not valid, rejected');
        _this.protocol.invalid_hash(peer, msg);
        return;
      }

      //verify their ID
      var vid = _this.hashKey(pkey);
      if(vid != data.id) {
        console.log('   -> peer id not valid, rejected');
        console.log('   %s != %s', data.id, vid);
        _this.protocol.invalid_id(peer, msg);
        return;
      }

      console.log(" - peer registered itself with the network");
      console.log("   -> id = %s", vid);
      console.log("   -> IP = %s", peer.ip);
      var nobj = {
        id:
          data.id,
        pkey:
          pkey,
        info:
          JSON.parse(info),
        infohash: 
          infohash
      }
      
      peer.id = nobj.id;

      _this.nodeidx[nobj.id] = nobj;
      _this.transmitnode(nobj);
      _this.saveData();
      _this.protocol.connect_accept(peer, msg);
    }
  };
};

Airnet.prototype.refreship = function() {
  var _this = this;
  var ipAddr = '';
  if(this.config.ip === ""){
    var req = http.request({hostname: 'jsonip.com'}, function(res) {
      res.setEncoding('utf8');
      res.on('data', function (chunk) {
        ipAddr += chunk;
      });
      res.on('end', function() {
        _this.publicaddr = JSON.parse(ipAddr).ip+":"+_this.port;
        console.log(" - public address resolved "+_this.publicaddr);
      });
    });
    req.on('error', function(e){
      console.log(" ! error finding public IP: "+e);
      console.log(" ! using local ip instead");
      require('dns').lookup(require('os').hostname(), function (err, add, fam) {
          console.log(' - addr: '+add);
          _this.publicaddr = add+":"+_this.port;
      });
    });
    req.end();
  }else{
    this.publicaddr = this.config.ip+":"+this.port;
  }
};

Airnet.prototype.transmitnode = function(node) {
  console.log(" - transmitting new node definition");
  var msg = {newclient: new GOSSIP_NEWCLIENT({
    id: node.id,
    pkey: node.pkey,
    info: JSON.stringify(node.info),
    infohash: node.infohash,
    retrans: true
  })};

  var _this = this;
  this.peers.forEach(function(peer){
    if(peer.id != msg.id)
      _this.sendMessage(peer.ws, msg);
  });
};

Airnet.prototype.sendMessage = function(ws, gmsg) {
  gmsg["time"] = genTimestamp();
  gmsg["timehash"] = ursa.coercePrivateKey(this.privkey).hashAndSign("sha256", gmsg["time"].encode().toBuffer());
  ws.send(new GOSSIP_MESSAGE(gmsg).encode().toBuffer());
};

Airnet.prototype.hashKey = function(key) {
  var hasher = getHashSum();
  hasher.update(key.toString());
  return hasher.digest('hex');
};

Airnet.prototype.generateKeyAndID = function() {
  var key = ursa.generatePrivateKey();
  this.privkey = ursa.coercePrivateKey(key.toPrivatePem().toString());
  this.pubkey = ursa.coercePublicKey(key.toPublicPem().toString());
  this.id = this.hashKey(this.pubkey.toPublicPem().toString());
  console.log(" - generated new identity:");
  console.log("   -> ID = "+this.id);
};

Airnet.prototype.saveData = function() {
  if(this.config.usefile) {
    var speers = [];

    for(var key in this.nodeidx) {
      var value = this.nodeidx[key];
      speers.push(
        new speer({
          id: value.id,
          pkey: value.pkey,
          info: JSON.stringify(value.info),
          infohash: value.infohash
        })
      );
    }

    var connections = [];
    for(var i=0;i<this.peers.length;i++){
      var cip = this.peers[i].ip;
      if(!_.contains(connections, cip))
        connections.push(cip);
    }

    var sobj = {
      id:
        this.id,
      key:
        this.privkey.toPrivatePem().toString(),
      pkey:
        this.pubkey.toPublicPem().toString(),
      peers:
        speers,
      info:
        JSON.stringify(this.clientinfo),
      connections:
        connections
    }
    var sdata = new ssave(sobj);//also peers need to be serialized here
    var fd =  fs.openSync(this.config.file, 'w');
    var buff = sdata.encode().toBuffer();
    fs.writeSync(fd, buff, 0, buff.length, 0);
    console.log(" - wrote save file");
  }
  else {
    console.log(" - no save option enabled, not saving!");
  }
}
Airnet.prototype.saveDefaultSettings = function(fpath) {
  this.generateKeyAndID();
  this.saveData();
};

Airnet.prototype.loadSettings = function(fpath) {
  var data = fs.readFileSync(fpath);
  var pdata = ssave.decode(data);
  //we want to recalculate our ID just to be sure
  try {
    var priv = pdata.key.toString('utf8');
    var pub = pdata.pkey.toString('utf8');
    this.pubkey = ursa.coercePublicKey(pub);
    this.privkey = ursa.coercePrivateKey(priv);
    this.id = this.hashKey(pub);
    this.clientinfo = JSON.parse(pdata.info);
    var prs = pdata.peers;
    for(var i=0; i<prs.length; i++)
    {
      var peer = prs[i];
      this.nodeidx[peer.id] = {
        id:
          peer.id,
        pkey:
          peer.pkey,
        info:
          JSON.parse(peer.info),
        infohash:
          peer.infohash
      };
    }

    if(pdata.connections == undefined)
      pdata.connections = [];

    if(this.config.autoconnect){
      for(var i=0;i<pdata.connections.length;i++){
        this.connect(pdata.connections[i]);
      }
    }

    console.log(" - Loaded keys, id: "+this.id);
  } catch(err) {
    console.log(" ! err loading keys, backing up save "+err);
    var path = this.config.file;
    fs.createReadStream(path).pipe(fs.createWriteStream(path+".bak"));
    console.log(" - backed up, using new keys.");
    return this.saveDefaultSettings();
  }
};

Airnet.prototype.autoConnectThread = function(_this){
  var alreadyTried = [];
  //All of the peers we should attempt to connect to
  while(!_this.stop){
    sleep(1000);
    if(_this.peersToTry.length != 0){
      _this.peersToTry = _.uniq(_this.peersToTry);
      var ip = _this.peersToTry.pop();
      if(!_.contains(alreadyTried, ip)){
        var epeer = _.findWhere(_this.peers, {ip: ip});
        //Check if we're already connected
        if(epeer == undefined){
          _this.connect(ip);
          alreadyTried.push(ip);
        }
      }
    }
  }
};

Airnet.prototype.printConnectedPeers = function(){
  console.log(" === "+this.peers.length+" connected peers ===");
  for(var i=0;i<this.peers.length;i++){
    console.log("  -> %s, %s", this.peers[i].ip, this.peers[i].id);
  }
};

Airnet.prototype.handleAuthErrors = function(msg, peer){
  if(msg.invalidhash){
    console.log(" ! peer does not verify our message hash");
    console.log("   -> network does not believe we are who we say we are");
    console.log("   -> therefore connect attempt failed");
    peer.ws.close();
    return true;
  }
  if(msg.invalidtime){
    console.log(" ! peer says our timestamp is too old/unreasonably new");
    if(msg.invalidtime.remotetime)
    {
      console.log("  -> remote time: "+remotetime);
      console.log("  -> current time: "+new Date().getTime());
    }
    console.log("  -> therefore connect attempt failed");
    peer.ws.close();
    return true;
  }
  if(msg.invalidid){
    console.log(" ! peer says our ID is invalid");
    console.log("   -> therefore connect attempt failed");
    peer.ws.close();
    return true;
  }
  return false;
};

Airnet.prototype.processMessage = function(msg, peer) {
  if(msg.connectunknown) {
    this.protocolr.connect_unknown(peer, msg);
    return;
  }
  if(peer.connecting) { //We are connecting to this peer
    if(msg.connectaccept)
    {
      console.log(" - peer accepted us, checking their info");
      peer.connecting = false;
    }
    else if(this.handleAuthErrors(msg, peer)) {
      return;
    }else{
      console.log(" - unknown response message");
      return;
    }
  }

  var spr = null;
  if(peer.id != undefined) {
    spr = this.nodeidx[peer.id];
  } else if(msg.connectinit) {
    spr = this.nodeidx[msg.connectinit.id];
    console.log(' - new peer connected');
    console.log('   -> id = %s', msg.connectinit.id);
    console.log('   -> ip = %s', msg.connectinit.ip);
    //todo: verify ip looks like an IP address
    peer.ip = msg.connectinit.ip;
  } else if(msg.connectaccept)
  {
    spr = this.nodeidx[msg.connectaccept.id];
  } else if(msg.connectnc) {
    spr = {
      pkey:
        msg.connectnc.pkey
    }
  }

  if(spr == null) {
    console.log('   -> peer unknown, requesting more info');
    this.sendMessage(peer.ws, {connectunknown: new CONNECT_UNKNOWN({moreinfo: true})});
    return;
  }

  var pkey = spr.pkey;
  var cpkey = ursa.coercePublicKey(pkey);
  var valid = cpkey.hashAndVerify("sha256", msg.time.encode().toBuffer(), msg.timehash.toBuffer());
  var timeInRange = ((new Date().getTime())-msg.time.time)<=30000;

  if(!valid)
  {
    console.log("    -> invalid time signature, rejected");
    this.protocol.invalid_sig(peer, msg);
    return;
  }

  if(!timeInRange) {
    console.log("   -> curr time: "+new Date().getTime()+" given time: "+msg.time.time);
    console.log("   -> time out of range, rejected");
    this.protocol.invalid_time(peer, msg);
    return;
  }

  if(msg.newclient) {
    if(this.nodeidx[msg.newclient.id] == undefined)
    {
      this.protocolr.gossip_newclient(peer, msg);
    }
  }

  if(msg.connectunknown) {
    //If we reach this point, they have connected to us but don't know who we are
    this.protocolr.connect_unknown(peer, msg);
  }

  if(msg.connectinit && peer.id == undefined) {
    console.log("   -> recognized, accepted.");
    peer.id = spr.id;
    this.peers.push(peer);
    this.printConnectedPeers();
    this.protocol.connect_accept(peer, msg);
    this.protocol.gossip_peers(peer, msg);
    this.saveData();
  }


  if(msg.connectnc)
  {
    this.protocolr.connect_newclient(peer, msg);
  }

  if(msg.peerlist){
    this.protocolr.gossip_peers(peer, msg);
  }

  if(msg.connectaccept) {
    //If we reach this point, they accepted us and we know who they are
    console.log("   -> ID = "+spr.id);
    console.log("   -> IP = "+peer.ip);
    console.log("   -> Verified, accepted.");
    peer.id = spr.id;
    this.peers.push(peer);
    this.printConnectedPeers();
    this.protocol.gossip_peers(peer, msg);
    this.saveData();
  }
};

Airnet.prototype.registerServerCallbacks = function() {
  var _this = this;
  this.wss.on('connection', function(ws) {
    var peer = {
      ws: ws
    };

    if(_.findWhere(_this.peers, {ip: peer.ip}) != undefined)
    {
      console.log(" - incoming already connected to "+peer.ip);
      console.log("   -> already connected: "+p.ip);
      console.log("   -> new peer: "+peer.ip);
      ws.close();
      return;
    }

    ws.on('message', function(message) {
      if(typeof message === 'string') {
        console.log(" - received a string, we expect binary buffers only");
        return;
      }
      var msg = GOSSIP_MESSAGE.decode(message);
      _this.processMessage(msg, peer);
    });

    ws.on('close', function() {
      if(peer.id != undefined) {
        var epeer = _.findWhere(_this.peers, {id: peer.id});
        if(epeer != undefined)
        {
          _this.peers.splice(_.indexOf(_this.peers, epeer), 1);
        }
        console.log(" - peer disconnected");
        console.log("   -> id = "+peer.id);
        _this.peersToTry.push(peer.ip);
      }
    });
  });
};

Airnet.prototype.setupPeerListeners = function(peer) {
  var _this = this;
  peer.ws.on('close', function() {
    if(peer.id != undefined) {
      var epeer = _.findWhere(_this.peers, {id: peer.id});
      if(epeer != undefined)
      {
        _this.peers.splice(_.indexOf(_this.peers, epeer), 1);
      }
      console.log(" - peer disconnected");
      console.log("   -> id = "+peer.id);
      _this.peersToTry.push(peer.ip);
    }
  });

  peer.ws.on('open', function() {
    console.log(' - connected to node: '+peer.ip);
    peer.connecting = true;
    _this.protocol.connect_init(peer);
  });

  peer.ws.on('message', function(message) {
    var msg = GOSSIP_MESSAGE.decode(message);
    _this.processMessage(msg, peer);
  });

  peer.ws.on('error', function(err){
    console.log(" - ws error: "+err);
  });
};

Airnet.prototype.procConnectQueue = function(){
  this.connectqueue = _.uniq(this.connectqueue);
  while(this.connectqueue.length != 0){
    var ip = this.connectqueue.pop();
    var ipp = ip.split(":");
    if(ip === this.publicaddr || ((ipp[0] === "127.0.0.1" || ipp[0] === "localhost") && parseInt(ip[1]) == this.port))
    {
      console.log(" ! we can't connect to ourselves.");
      return;
    }

    if(this.wss == null) {
      console.log(" ! call start() before connect().");
      return;
    }

    for(p in this.peers) {
      var peer = this.peers[p];
      if(peer.ip === ip)
      {
        console.log(" - already connected to "+ip);
        return;
      }
    }

    console.log(" - attempting to connect to %s", ip);

    try {
      var peer = {
        ws:
          new WebSocket('ws://'+ip+'/air'),
        ip:
          ip
      }
      this.setupPeerListeners(peer);
    } catch(err) {
      console.log(" - can't connect to "+ip);
    }
  }
};

Airnet.prototype.connect = function(ip) {
  this.connectqueue.push(ip);
};

Airnet.prototype.loadData = function() {
  if(this.config.usefile)
  {
    if(fs.existsSync(this.config.file))
      this.loadSettings(this.config.file);
    else
      this.saveDefaultSettings(this.config.file);
  } else {
    console.log(" - no save method specified");
    console.log(" - generating ephemeral airnet identity");
    this.generateKeyAndID();
  }
};

Airnet.prototype.connectThread = function(_this){
  while(!_this.stop){
    if(_this.publicaddr != undefined){
      _this.procConnectQueue();
    }
    sleep(200);
  }
};

Airnet.prototype.start = function() {
  var _this = this;
  Fiber(function(){
    if(_this.wss != null) {
      console.log("Airnet already started, but start() called a second time. Ignoring.");
      return;
    }

    _this.refreship();
    _this.loadData();
    _this.wss = new WebSocketServer({port: _this.port});
    _this.registerServerCallbacks();
    if(_this.config.autoconnect){
      Fiber(_this.autoConnectThread).run(_this);
    } 
    Fiber(_this.connectThread).run(_this);
    console.log(" - airnet started");
  }).run();
};

module.exports = Airnet;
