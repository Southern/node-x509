var x509 = require('./build/Release/x509');
var fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

exports.verify = function(certPath, CABundlePath){
  if(!certPath){
    throw new Error('Certificate path is required');
  };
  if(!CABundlePath){
    throw new Error('CA Bundle path is required');
  };

  fs.statSync(certPath);
  fs.statSync(CABundlePath);
  return x509.verify(certPath, CABundlePath);
};


exports.parseCert = function(path) {
  var ret = x509.parseCert(path);
  var exts = {};
  for (var key in ret.extensions) {
    var newkey = key.replace('X509v3', '').replace(/ /g, '');
    newkey = newkey.slice(0, 1).toLowerCase() + newkey.slice(1);
    exts[newkey] = ret.extensions[key];
  }
  delete ret.extensions;
  ret.extensions = exts;
  return ret;
};
