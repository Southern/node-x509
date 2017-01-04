var x509 = require('./build/Release/x509');
var fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

function x509_verify(certPathOrString, CABundlePathOrString, cb) {
  try {
    var ret = x509.parseCert(String(certPathOrString));
  }
  catch(Exception) {
    return cb(new TypeError('Unable to parse certificate.'));
  }

  try {
    x509.verify(certPathOrString, CABundlePathOrString);
    cb(null);
  }
  catch (verificationError) {
    cb(verificationError);
  }
}
function x509_verify_stat(certPathOrString, CABundlePathOrString, cb) {
  if (String(CABundlePathOrString).startsWith('---')) {
    return x509_verify(String(certPathOrString), CABundlePathOrString, cb);
  }

  fs.stat(CABundlePathOrString, function(bundlePathErr) {
    if (bundlePathErr) {
      return cb(bundlePathErr);
    }
    return x509_verify(String(certPathOrString), CABundlePathOrString, cb);
  })
}

exports.verify = function(certPathOrString, CABundlePathOrString, cb) {
  if (!certPathOrString) {
    throw new TypeError('Certificate path is required');
  }
  if (!CABundlePathOrString) {
    throw new TypeError('CA Bundle path is required');
  }

  if (String(certPathOrString).startsWith('---')) {
    return x509_verify_stat(String(certPathOrString), CABundlePathOrString, cb);
  }

  fs.stat(certPathOrString, function(certPathErr) {
    if (certPathErr) {
      return cb(certPathErr);
    }
    return x509_verify_stat(certPathOrString, CABundlePathOrString, cb);
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
