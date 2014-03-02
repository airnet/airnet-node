var crypto = require('crypto');
var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;
var ip = require('ip');
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

var getHashSum = function(){
  return crypto.createHash('sha256');
};

var genTimestamp = function(){
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
  //Global index of nodes
  this.nodeidx = {};

  this.config = {
    autoconnect: true,
    usefile: true,
    file: appDir+'/data.airnet'
  };

  this.refreship = function(){
    _this.publicaddr = ip.address()+":"+_this.port;
  }

  if (config != null){
    var k;
    for(k in config){
      v = config[k];
      if(this.config[k] != undefined)
        this.config[k] = v;
    }
  }

  this.protocol = {
    invalid_id: function(peer, msg){
      var msg = new INVALID_ID({invalid:msg});
      _this.sendMessage(peer.ws, {invalidid: msg});
    },
    invalid_sig: function(peer, msg){
      var msg = new INVALID_HASH({invalid: msg});
      _this.sendMessage(peer.ws, {invalidhash: msg});
    },
    invalid_time: function(peer, msg){
      var msg = new INVALID_TIME({invalid: msg});
      _this.sendMessage(peer.ws, {invalidtime: msg});
    },
    connect_init: function(peer){
      var msg = new CONNECT_INIT({
        id: _this.id
      }); 
      _this.sendMessage(peer.ws, {connectinit: msg});
    },
    connect_newclient: function(peer){
      var msg = new CONNECT_NEWCLIENT({
        id: _this.id,
        pkey: _this.pubkey.toPublicPem().toString(),
        info: JSON.stringify(_this.clientinfo),
        infohash: _this.privkey.hashAndSign("sha256", JSON.stringify(_this.clientinfo))
      });
      _this.sendMessage(peer.ws, {connectnc: msg});
    } 
  };

  //todo:
  //   - implement invalid_sig
  //   - implement invalid_time
  //   - implement gossip_rmnode
  //   - implement gossip_newclient
  //   - implement connect_newclient
  this.protocolr = {
    connect_init: function(peer, msg){
      var data = msg.connectinit;
      console.log(' - new peer connected');
      console.log('   -> id = %s', data.id);
      var spr = _this.nodeidx[data.id];
      if(spr == undefined){
        var msg = new CONNECT_UNKNOWN({
          moreinfo: true
        });
        console.log('   -> peer unknown, requesting more info');
        _this.sendMessage(peer.ws, {connectunknown: msg});
        return;
      }else{
        //Assert the timestamp is OK
        var pkey = spr.pkey; 
        var cpkey = ursa.coercePublicKey(pkey);
        var valid = cpkey.hashAndVerify("sha256", msg.time.encode().toBuffer(), msg.timehash, "utf8");
        //within 30 seconds
        //potential security bug - what if it's in the future?
        var timeInRange = ((new Date().getTime())-msg.time.time)<=30000;
        if(!valid)
        {
          console.log("    -> invalid time signature, rejected");
          _this.protocol.invalid_sig(peer, msg);
        }else if(!timeInRange){
          console.log("   -> time out of range, rejected");
          _this.protocol.invalid_time(peer, msg);
        }
        else{
          console.log("   -> recognized, accepted.");
          peer.id = data.id;
          _this.peers.push(peer);
        }
      } 
    },
    connect_unknown: function(peer, msg){
      var data = msg.connectunknown;
      if(data.moreinfo){
        console.log(' - sending more info to peer');
        _this.protocol.connect_newclient(peer);
      }
    },
    connect_newclient: function(peer, msg){
      var data = msg.connectnc;
      //verify hash
      var pkey = data.pkey;
      var info = data.info;
      var infohash = data.infohash;
      var cpkey = ursa.coercePublicKey(pkey);
      
      var valid = cpkey.hashAndVerify("sha256", info, infohash.toBuffer(), "utf8");

      if(!valid){
        console.log('   -> peer signature not valid, rejected');
        _this.protocol.invalid_hash(peer, msg);
        return;
      }

      //verify their ID
      var vid = _this.hashKey(pkey);
      if(vid != data.id){
        console.log('   -> peer id not valid, rejected');
        console.log('   %s != %s', data.id, vid);
        _this.protocol.invalid_id(peer, msg);
        return;
      }

      console.log(" - peer registered itself with the network");
      console.log("   -> id = %s", vid);
      var nobj = {
        id: vid,
        pkey: pkey,
        info: JSON.parse(info)
      } 
      _this.nodeidx[nobj.id] = nobj;
      _this.transmitnode(nobj);
      _this.saveData();
    }
  };


};

Airnet.prototype.transmitnode = function(node){
  //todo: send the node to all connected peers
  console.log(" - transmitting new node definition");
};

Airnet.prototype.sendMessage = function(ws, gmsg){
  gmsg["time"] = genTimestamp();
  gmsg["timehash"] = ursa.coercePrivateKey(this.privkey).hashAndSign("sha256", gmsg["time"].encode().toBuffer()); 
  ws.send(new GOSSIP_MESSAGE(gmsg).encode().toBuffer());
};

Airnet.prototype.hashKey = function(key){
  var hasher = getHashSum();
  hasher.update(key.toString());
  return hasher.digest('hex');
};

Airnet.prototype.generateKeyAndID = function(){
  var key = ursa.generatePrivateKey();
  this.privkey = ursa.coercePrivateKey(key.toPrivatePem().toString());
  this.pubkey = ursa.coercePublicKey(key.toPublicPem().toString());
  this.id = this.hashKey(this.pubkey.toPublicPem().toString());
};

Airnet.prototype.saveData = function(){
  if(this.config.usefile){
    var peers = [];

    for(var key in this.nodeidx){
      var value = this.nodeidx[key];
      peers.push(
          new speer({
            id: value.id,
            pkey: value.pkey,
            info: JSON.stringify(value.info)
          })
      );
    }

    var sobj = {
      id: this.id,
      key: this.privkey.toPrivatePem().toString(),
      pkey: this.pubkey.toPublicPem().toString(),
      peers: peers,
      info: JSON.stringify(this.clientinfo)
    }
    var sdata = new ssave(sobj);//also peers need to be serialized here
    var fd =  fs.openSync(this.config.file, 'w');
    var buff = sdata.encode().toBuffer();
    fs.writeSync(fd, buff, 0, buff.length, 0);
    console.log(" - wrote save file");
  }
  else{
    console.log(" - no save option enabled, not saving!");
  }
}
Airnet.prototype.saveDefaultSettings = function(fpath){
  this.generateKeyAndID();
  this.saveData();
};

Airnet.prototype.loadSettings = function(fpath){
  var data = fs.readFileSync(fpath);
  var pdata = ssave.decode(data);
  //we want to recalculate our ID just to be sure
  try{
    var priv = pdata.key.toString('utf8');
    var pub = pdata.pkey.toString('utf8');
    this.pubkey = ursa.coercePublicKey(pub);
    this.privkey = ursa.coercePrivateKey(priv);
    this.id = this.hashKey(pub);
    this.clientinfo = JSON.parse(pdata.info);
    var prs = pdata.peers;
    for(var peer in prs){
      console.log(peer.info);
      this.nodeidx[peer.id] = {
        id: peer.id,
        pkey: peer.pkey,
        info: JSON.parse(peer.info)
      };
    }
    console.log(" - Loaded keys, id: "+this.id);
  }catch(err){
    console.log(" ! err loading keys, backing up save "+err);
    var path = this.config.file;
    fs.createReadStream(path).pipe(fs.createWriteStream(path+".bak"));
    console.log(" - backed up, using new keys.");
    return this.saveDefaultSettings();
  }
};

Airnet.prototype.processMessage = function(msg, peer){
  if(msg.newclient){
    console.log(' - gossip new client');
  }

  if(msg.connectinit){
    this.protocolr.connect_init(peer, msg);
  }

  if(msg.connectunknown){
    this.protocolr.connect_unknown(peer, msg);
  }

  if(msg.connectnc)
  {
    this.protocolr.connect_newclient(peer, msg);
  }
};

Airnet.prototype.registerServerCallbacks = function(){
  var _this = this;
  this.wss.on('connection', function(ws){
    var peer = {
      ws: ws,
    ip: ws._socket.address().address+":"+ws._socket.address().port
    };

    for(p in _this.peers){
      if(peer.ip === p.ip)
  {
    console.log(" - incoming already connected to "+ip);
    ws.close();
    return;
  }
    }

    ws.on('message', function(message){
      if(typeof message === 'string'){
        console.log(" - received a string, we expect binary buffers only");
        return;
      }
      var msg = GOSSIP_MESSAGE.decode(message);
      _this.processMessage(msg, peer); 
    });

    ws.on('close', function(){
      //todo: delete peer from this.peers
      if(peer.id != undefined){
        var idx = _.findWhere(_this.peers, {id: peer.id});
        if(idx > -1)
    {
      _this.peers.splice(idx, 1);
    }
    console.log(" - peer disconnected");
    console.log("   -> id = "+peer.id);
      }
    });
  });
};

Airnet.prototype.setupPeerListeners = function(peer){
  var _this = this;
  peer.ws.on('close', function(){
    console.log(" - node disconneted: "+peer.ip);
    //todo: delete peer from this.peers
  });

  peer.ws.on('open', function(){
    console.log(' - connected to node: '+peer.ip);
    _this.protocol.connect_init(peer);
  });

  peer.ws.on('message', function(message){
    var msg = GOSSIP_MESSAGE.decode(message);
    _this.processMessage(msg, peer);
  });
};

Airnet.prototype.connect = function(ip){
  if(ip == this.publicaddr)
  {
    console.log(" ! we can't connect to ourselves.");
    return;
  }
  if(this.wss == null){
    console.log(" ! call start() before connect().");
    return;
  }
  for(p in this.peers){
    var peer = this.peers[p];
    if(peer.ip === ip)
    {
      console.log(" - already connected to "+ip);
      return;
    }
  }

  try{
    var peer = {
      ws: new WebSocket('ws://'+ip+'/air'),
      ip: ip
    }
    this.peers.push(peer);
    this.setupPeerListeners(peer);
  }catch(err){
    console.log(" - can't connect to "+ip);
  }
};

Airnet.prototype.loadData = function(){
  if(this.config.usefile)
  {
    if(fs.existsSync(this.config.file))
      this.loadSettings(this.config.file);
    else
      this.saveDefaultSettings(this.config.file);
  }else{
    console.log(" - no save method specified");
    console.log(" - generating ephemeral airnet identity");
    this.generateKeyAndID();
  }
}

Airnet.prototype.start = function(){
  if(this.wss != null){
    console.log("Airnet already started, but start() called a second time. Ignoring.");
    return;
  }
  this.refreship();
  this.loadData();
  this.wss = new WebSocketServer({port: this.port});
  this.registerServerCallbacks();
  console.log(" - airnet started, ip: "+this.publicaddr);
};

module.exports = Airnet;
