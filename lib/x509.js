var x509Native = require("../build/Release/x509");
var x509 = module.exports;
var moment = require('moment');

x509.getAltNames = function(cert) {
  return x509Native.getAltNames(cert);
};

x509.getIssuer = function(cert) {
  return x509Native.getIssuer(cert);
};

x509.getSubject = function(cert) {
  return x509Native.getSubject(cert);
};

x509.parseCert = function(cert) {
  var parsed = x509Native.parseCert(cert);
  // convert notBefore and not After
  parsed.notBefore = moment.utc(parsed.notBefore, 'YYMMDDhhmmss').toDate();
  parsed.notAfter = moment.utc(parsed.notAfter, 'YYMMDDhhmmss').toDate();
  return parsed;
};