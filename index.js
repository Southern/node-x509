var x509 = require('./build/Release/x509');
var fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

exports.verify = function(certPath, CABundlePath, cb) {
  if (!certPath) {
    throw new TypeError('Certificate path is required');
  }
  if (!CABundlePath) {
    throw new TypeError('CA Bundle path is required');
  }

  fs.stat(certPath, function(certPathErr) {

    if (certPathErr) {
      return cb(certPathErr);
    }

    fs.stat(CABundlePath, function(bundlePathErr) {

      if (bundlePathErr) {
        return cb(bundlePathErr);
      }

      try {
        x509.verify(certPath, CABundlePath);
        cb(null);
      }
      catch (verificationError) {
        cb(verificationError);
      }
    });
  });
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
