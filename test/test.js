var x509 = require('../lib/x509'),
    fs = require('fs'),
    path = require('path');

// All cert files should read without throwing an error.
// Simple enough test, no?
fs.readdirSync(path.join(__dirname, 'certs')).forEach(function (file) {
  console.log("File: %s", file);
  console.log(x509.parseCert(path.join(__dirname, 'certs', file)));
  console.log();
});
