
var x509 = require('./build/Release/x509');
var assert = require('assert');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;
// exports.verify = x509.verify;

exports.verify = function(certPath, CABundlePath){
  assert(certPath, 'certificate path is required');
  assert(CABundlePath, 'certificate path is required');
  console.log(certPath, CABundlePath)
  return x509.verify(certPath, CABundlePath);
}


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
