var x509 = require('./build/Release/x509');
var fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

exports.verifyFromStr = function(certStr, CABundleStr, cb) {
  if (typeof cb !== 'function') {
    throw new Error('cb should be function');
  }
  if (certStr instanceof Buffer) {
    certStr = certStr.toString();
  } else if (typeof certStr !== 'string') {
    cb(new Error('certStr should be string or buffer'));
    return;
  }
  if (CABundleStr instanceof Buffer) {
    CABundleStr = CABundleStr.toString();
  } else if (typeof CABundleStr !== 'string') {
    cb(new Error('CABundleStr should be string or buffer'));
    return;
  }
  var caughtErr = null;
  try {
    x509.verify_from_str(certStr, CABundleStr);
  } catch (verificationError) {
    caughtErr = verificationError;
  } finally {
    cb(caughtErr);
  }
};

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
      } catch (verificationError) {
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
