// eslint-disable-next-line node/no-unpublished-require
const x509 = require('./build/Release/x509');
const fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

exports.verify = function (certPath, CABundlePath, cb) {
  if (!certPath) {
    throw new TypeError('Certificate path is required');
  }

  if (!CABundlePath) {
    throw new TypeError('CA Bundle path is required');
  }

  fs.stat(certPath, function (certPathErr) {
    if (certPathErr) {
      return cb(certPathErr);
    }

    fs.stat(CABundlePath, function (bundlePathErr) {
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

exports.parseCert = function (path) {
  const cert = x509.parseCert(path);
  const extensions = {};

  for (const key in cert.extensions) {
    let newKey = key.replace('X509v3', '').replace(/ /g, '');
    newKey = newKey.slice(0, 1).toLowerCase() + newKey.slice(1);
    extensions[newKey] = cert.extensions[key];
  }

  delete cert.extensions;
  cert.extensions = extensions;

  return cert;
};
