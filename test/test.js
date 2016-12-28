var x509 = require('../index'),
    fs = require('fs'),
    path = require('path'),
    assert = require('assert');

// All cert files should read without throwing an error.
// Simple enough test, no?
fs.readdirSync(path.join(__dirname, 'certs')).forEach(function (file) {
  if (file === 'enduser-example-bad.com.crt') return;
  console.log("File: %s", file);
  console.log(x509.parseCert(path.join(__dirname, 'certs', file)));
  // x509.parseCert(path.join(__dirname, 'certs', file));
  console.log();
});


x509.verify(
  path.join(__dirname, 'certs/enduser-example.com.crt'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err) {
    console.log('x509 verify');
    assert.strictEqual(err, null);
  }
);

x509.verify( fs.readFileSync(path.join(__dirname, 'certs/enduser-example.com.crt')),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err) {
    console.log('x509 verify string input');
    assert.strictEqual(err, null);
  }
);

x509.verify(
  fs.readFileSync(path.join(__dirname, 'certs/enduser-example-bad.com.crt')),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err) {
    console.log('x509 verify invalid cert');
    assert.throws(assert.ifError.bind(null, err), /Unable to parse certificate./)
  }
);

x509.verify(
  '--- BEGIN CERTIFICATE ---\n' +
  'this is not the certificate you are looking for...\n' +
  '--- END CERTIFICATE ---',
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err) {
    console.log('x509 verify invalid cert string input');
    assert.throws(assert.ifError.bind(null, err), /Unable to parse certificate./)
  }
);

x509.verify(
  fs.readFileSync(path.join(__dirname, 'certs/enduser-example-malformed.com.crt')),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err) {
    console.log('x509 verify altered cert');
    assert.throws(assert.ifError.bind(null, err), /certificate signature failure/)
  }
);


x509.verify(
  path.join(__dirname, 'certs/acaline.com.crt'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err, result) {
    console.log('x509 verify no local issuer');
    assert.throws(assert.ifError.bind(null, err), /unable to get local issuer/)
  }
);

x509.verify(
  path.join(__dirname, 'certs/notexisting.com.crt'),
  path.join(__dirname, 'CA_chains/enduser-example.com.chain'),
  function (err, result) {
    console.log('x509 verify no local file');
    assert.throws(assert.ifError.bind(null, err), /ENOENT/)
  }
);
