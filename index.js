var Promise = require('promise-polyfill'); // Needed since we're supporting Node 0.10 environments

var x509 = require('./build/Release/x509');
var fs = require('fs');

exports.version = x509.version;
exports.getAltNames = x509.getAltNames;
exports.getSubject = x509.getSubject;
exports.getIssuer = x509.getIssuer;

exports.verify = function(certPathOrString, CABundlePathOrString, cb) {
  if (!certPathOrString) {
    throw new TypeError('The certificate path or the certificate string itself is required');
  }
  if (!CABundlePathOrString) {
    throw new TypeError('The certificate bundle path or the bundle string itself is required');
  }

  Promise.all([
    getPathOrStringBuffer(certPathOrString),
    getPathOrStringBuffer(CABundlePathOrString)
  ]).then(function(results){
    var certBuffer = results[0];
    var caBuffer = results[1];

    try {
      var parsedCert = x509.parseCert(String(certBuffer));
    } catch(Exception) {
      return cb(new TypeError('Unable to parse certificate.'));
    }

    try {
      x509.verify(certBuffer, caBuffer);
      cb(null, parsedCert); //Might as well pass back the parsed certificate on verify
    } catch (verificationError) {
      cb(verificationError);
    }
  }, cb);
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

function getPathOrStringBuffer(pathOrString){
  if(String(pathOrString).indexOf('-----BEGIN') === 0){
    return Promise.resolve(Buffer(pathOrString, 'utf8'));
  } else{
    return new Promise(function(res, rej){
      fs.readFile(pathOrString, function(err, fileBuffer){
        if(err){
          return rej(err);
        }
        res(fileBuffer)
      })
    });
  }
}