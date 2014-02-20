var WebSocket = require('ws');
var ip = require('ip');

var Airnet = function(port, config)
{
  var state = 0;
  var ws = null;
  var _this = this;
  this.port = port;
  this.config = {
    autoconnect: true,
    sqlite: false //not implemented yet
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

  this.start = function(){
  }
};

Airnet.prototype.start = function(){
  this.refreship();
  this.ws = new WebSocket('ws://'+_this.publicaddr+':'+_this.port+'/air'); 
};

module.exports = Airnet;
