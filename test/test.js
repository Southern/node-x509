var x509 = require('../index'),
    fs = require('fs'),
    path = require('path'),
    assert = require('assert');

// All cert files should read without throwing an error.
// Simple enough test, no?
fs.readdirSync(path.join(__dirname, 'certs')).forEach(function (file) {
  console.log("File: %s", file);
  console.log(x509.parseCert(path.join(__dirname, 'certs', file)));
  // x509.parseCert(path.join(__dirname, 'certs', file));
  console.log();
});


x509.verify(
  path.join(__dirname, 'certs/enduser-example.com.crt'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err) {
    assert.strictEqual(err, null);
  }
);



x509.verify(
  path.join(__dirname, 'certs/acaline.com.crt'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err, result) {
    assert.throws(assert.ifError.bind(null, err), /unable to get local issuer/)
  }
);

x509.verify(
  path.join(__dirname, 'certs/notexisting.com.crt'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err, result) {
    assert.throws(assert.ifError.bind(null, err), /ENOENT/)
  }
);
