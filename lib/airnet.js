var crypto = require('crypto');
var WebSocket = require('ws');
var WebSocketServer = WebSocket.Server;
var ip = require('ip');
var Fiber = require('fibers');
var ProtoBuf = require('protobufjs');
var pbuilder = ProtoBuf.loadProtoFile("../airnet/proto/airnet.proto");
var path = require('path'),
        appDir = path.dirname(require.main.filename);
var sbuilder = ProtoBuf.loadProtoFile('data.proto');
var fs = require('fs');
var ursa = require('ursa');


//Message types
var speer = sbuilder.build("peer");
var ssave = sbuilder.build("save");

var getHashClass = function(){
  return crypto.createHash('sha256');
};

var Airnet = function(port, config)
{
  var state = 0;
  //Each peer is represented as key: id
  this.peers = {};
  this.wss = null;
  var _this = this;
  this.port = port;

  this.config = {
    autoconnect: true,
    usefile: true,
    file: appDir+'/data.airnet'
  };

  this.refreship = function(){
    _this.publicaddr = ip.address();
  }

  if (config != null){
    var k;
    for(k in config){
      v = config[k];
      if(this.config[k] != undefined)
        this.config[k] = v;
    }
  }

  if(this.config.usefile)
  {
    if(fs.existsSync(this.config.file))
      this.loadSettings(this.config.file);
    else
      this.saveDefaultSettings(this.config.file);
  }
};

Airnet.prototype.generateKeyAndID = function(){
  var hasher = getHashSum();
  var key = ursa.generatePrivateKey();
  this.privkey = key.toPrivatePem();
  this.pubkey = key.toPublicPem();
  hasher.update(this.pubkey.toString());
  this.id = hasher.digest('hex');
};

Airnet.prototype.saveDefaultSettings = function(fpath){
  this.generateKeyAndID();
  var sdata = new ssave({
    id: this.id,
    key: this.privkey,
    pkey: this.pubkey
  });//also peers need to be serialized here
  fs.writeFileSync(this.config.file, sdata.encode());
  console.log("Wrote save file.");
};

Airnet.prototype.loadSettings = function(fpath){
  var data = fs.readFileSync(fpath);
  var pdata = ssave.decode(data);
  //we want to recalculate our ID just to be sure
  try{
    this.pubkey = ursa.coercePublicKey(pdata.pkey);
    this.privkey = ursa.coercePrivateKey(pdata.key);
    var hasher = getHashSum();
    hasher.update(this.pubkey.toString());
    this.id = hasher.digest('hex');
    console.log("Loaded keys, id: "+this.id);
  }catch(err){
    console.log("Error loading keys, backing up save file. Error: "+err);
    var path = this.config.file;
    fs.createReadStream(path).pipe(fs.createWriteStream(path+".bak"));
    console.log(" ... backed up, using new keys.");
    return this.saveDefaultSettings();
  }
};

Airnet.prototype.registerServerCallbacks = function(){
  this.wss.on('connection', function(ws){
    ws.on('message', function(message){
      console.log('received %s', message);
    });
    ws.send('init');
    console.log('new connection');
  });
};

Airnet.prototype.protocol = {
  connect_init: function(peer){
     
  } 
};

Airnet.prototype.setupPeerListeners = function(peer){
  var _this = this;
  peer.ws.on('close', function(){
    console.log("node disconneted: "+peer.ip);
    if(peer.id != undefined)
      delete _this.peers[peer.key];
  });

  peer.ws.on('open', function(){
    console.log('connected to node: '+peer.ip);
  });
};

Airnet.prototype.connect = function(ip){
  if(this.wss == null){
    console.log("Airnet: call start() before connect().");
    return;
  }
  for(p in this.peers){
    var peer = this.peers[p];
    if(peer.ip === ip)
    {
      console.log("connect called, but already connected");
      return;
    }
  }
  var peer = {
    ws: new WebSocket('ws://'+ip+'/air'),
    ip: ip
  }
  this.setupPeerListeners(peer);
};

Airnet.prototype.start = function(){
  if(this.wss != null){
    console.log("Airnet already started, but start() called a second time. Ignoring.");
    return;
  }
  this.refreship();
  this.wss = new WebSocketServer({port: this.port});
  this.registerServerCallbacks();
};

module.exports = Airnet;
