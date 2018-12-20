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

x509.verify(
  path.join(__dirname, 'certs/equifax.crt'),
  path.join(__dirname, '/test.js'),
  function(err, result) {
    assert.throws(assert.ifError.bind(null, err), /Error loading CA chain file/)
  }
);

x509.verify(
  path.join(__dirname, '/test.js'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function(err, result) {
    assert.throws(assert.ifError.bind(null, err), /Failed to load cert/)
  }
);

x509.verifyFromStr(
  fs.readFileSync(path.join(__dirname, 'certs/enduser-example.com.crt')),
  fs.readFileSync(path.join(__dirname, 'CA_chains/enduser-example.com.chain')),
  function(err, result) {
    assert.strictEqual(err, null)
  }
);

x509.verifyFromStr(
  fs.readFileSync(path.join(__dirname, 'certs/acaline.com.crt')),
  fs.readFileSync(path.join(__dirname, 'CA_chains/enduser-example.com.chain')),
  function(err, result) {
    assert.throws(assert.ifError.bind(null, err), /self signed certificate/)
  }
);

x509.verifyFromStr(
  fs.readFileSync(path.join(__dirname, 'test.js')),
  fs.readFileSync(path.join(__dirname, 'CA_chains/enduser-example.com.chain')),
  function(err, result) {
    assert.throws(assert.ifError.bind(null, err), /Failed to load cert/)
  }
);

x509.verifyFromStr(
  fs.readFileSync(path.join(__dirname, 'certs/acaline.com.crt')),
  fs.readFileSync(path.join(__dirname, 'test.js')),
  function(err, result) {
    assert.throws(assert.ifError.bind(null, err), /Failed to load ca/)
  }
);

x509.verifyFromStr(
  123456,
  fs.readFileSync(path.join(__dirname, 'CA_chains/enduser-example.com.chain')),
  function(err, result) {
    assert.throws(assert.ifError.bind(null, err), /certStr should be string or buffer/)
  }
)

try {
  x509.verifyFromStr(
    fs.readFileSync(path.join(__dirname, 'certs/acaline.com.crt')),
    fs.readFileSync(path.join(__dirname, 'CA_chains/enduser-example.com.chain'))
  )
} catch (err) {
  assert.throws(assert.ifError.bind(null, err), /cb should be function/)
}