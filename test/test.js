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

function fillPath(filename) {
  return path.join(__dirname, filename)
}

function loadFile(filename) {
  return fs.readFileSync(fillPath(filename))
}


function x509_verify_test(cert_path, ca_path, cb) {
  x509.verify(fillPath(cert_path), fillPath(ca_path), cb);
  x509.verify(loadFile(cert_path), fillPath(ca_path), cb);
  x509.verify(fillPath(cert_path), loadFile(ca_path), cb);
  x509.verify(loadFile(cert_path), loadFile(ca_path), cb);
}

x509_verify_test(
  'certs/enduser-example.com.crt',
  'CA_chains/enduser-example.com.chain',
  function (err) {
    console.log('x509 verify');
    assert.strictEqual(err, null);
  }
);

x509_verify_test(
  'certs/enduser-example-bad.com.crt',
  'CA_chains/enduser-example.com.chain',
  function (err) {
    console.log('x509 verify invalid cert');
    assert.throws(assert.ifError.bind(null, err), /Unable to parse certificate./)
  }
);

x509_verify_test(
  'certs/enduser-example-malformed.com.crt',
  'CA_chains/enduser-example.com.chain',
  function (err) {
    console.log('x509 verify altered cert');
    assert.throws(assert.ifError.bind(null, err), /certificate signature failure/)
  }
);


x509_verify_test(
  'certs/acaline.com.crt',
  'CA_chains/enduser-example.com.chain',
  function (err, result) {
    console.log('x509 verify no local issuer');
    assert.throws(assert.ifError.bind(null, err), /unable to get local issuer/)
  }
);

x509.verify(
  'certs/notexisting.com.crt',
  'CA_chains/enduser-example.com.chain',
  function (err, result) {
    console.log('x509 verify no local file');
    assert.throws(assert.ifError.bind(null, err), /ENOENT/)
  }
);
