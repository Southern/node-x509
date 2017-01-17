var x509 = require('./build/Release/x509');
var fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

function x509_verify(certBuffer, caBuffer, cb) {
  try {
    x509.parseCert(String(certBuffer));
  }
  catch(Exception) {
    return cb(new TypeError('Unable to parse certificate.'));
  }

  try {
    x509.verify(certBuffer, caBuffer);
    cb(null);
  }
  catch (verificationError) {
    cb(verificationError);
  }
}

function x509_verify_cert_buffer_ca_buffer(certBuffer, caBuffer, cb) {
  x509_verify(certBuffer, caBuffer, cb);
}
function x509_verify_cert_buffer_ca_path(certBuffer, caPath, cb) {
  fs.stat(caPath, function(err) {
    if (err) {
      return cb(err);
    }
    x509_verify(certBuffer, fs.readFileSync(caPath), cb);
  })

}
function x509_verify_cert_path_ca_buffer(certPath, caBuffer, cb) {
  fs.stat(certPath, function(err) {
    if (err) {
      return cb(err);
    }
    x509_verify(fs.readFileSync(certPath), caBuffer, cb);
  })
}
function x509_verify_cert_path_ca_path(certPath, caPath, cb) {
  fs.stat(certPath, function(err) {
    if (err) {
      return cb(err);
    }
    fs.stat(caPath, function(err) {
      if (err) {
        return cb(err);
      }
      x509_verify(fs.readFileSync(certPath), fs.readFileSync(caPath), cb);
    })
  })
}

exports.verify = function(certPathOrString, CABundlePathOrString, cb) {
  if (!String.prototype.startsWith) {
    String.prototype.startsWith = function(searchString, position){
      position = position || 0;
      return this.substr(position, searchString.length) === searchString;
    };
  }
  if (!certPathOrString) {
    throw new TypeError('Certificate path is required');
  }
  if (!CABundlePathOrString) {
    throw new TypeError('CA Bundle path is required');
  }

  if (String(certPathOrString).startsWith('-----BEGIN')) {
    if (String(CABundlePathOrString).startsWith('-----BEGIN')) {
      return x509_verify(String(certPathOrString), CABundlePathOrString, cb);
    } else {
      return x509_verify_cert_buffer_ca_path(String(certPathOrString), CABundlePathOrString, cb);
    }
  } else {
    if (String(CABundlePathOrString).startsWith('-----BEGIN')) {
      return x509_verify_cert_path_ca_buffer(String(certPathOrString), CABundlePathOrString, cb);
    } else {
      return x509_verify_cert_path_ca_path(String(certPathOrString), CABundlePathOrString, cb);
    }
  }
};


exports.parseCert = function(pathOrBuffer) {
  var ret = x509.parseCert(pathOrBuffer);
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
