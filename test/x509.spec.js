const x509 = require('..');
const fs = require('fs');
const path = require('path');

const EACH_CERTS_PATH = fs.readdirSync(path.join(__dirname, 'certs'));

describe('x509', () => {
  it.each(EACH_CERTS_PATH)('%s should read without throwing an error', (file) => {
    x509.parseCert(path.join(__dirname, 'certs', file));
  });

  it('should verify the cert and not throw an error', (done) => {
    expect.hasAssertions();

    x509.verify(
      path.join(__dirname, 'certs/end-user-example.com.crt'),
      path.join(__dirname, 'chains/end-user-example.com.chain'),
      function (err) {
        expect(err).toBeNull();
        done();
      }
    );
  });

  it('should throw an error "unable to get local issuer"', (done) => {
    expect.hasAssertions();

    x509.verify(
      path.join(__dirname, 'certs/acaline.com.crt'),
      path.join(__dirname, 'chains/end-user-example.com.chain'),
      function (err) {
        expect(err.message).toMatch(/unable to get local issuer/);
        done();
      }
    );
  });

  it('should throw an error "ENOENT"', (done) => {
    expect.hasAssertions();

    x509.verify(
      path.join(__dirname, 'certs/not-existing.com.crt'),
      path.join(__dirname, 'CA_chains/end-user-example.com.chain'),
      function (err) {
        expect(err.message).toMatch(/ENOENT/);
        done();
      }
    );
  });

  it('should throw an error "Error loading CA chain file"', (done) => {
    expect.hasAssertions();

    x509.verify(
      path.join(__dirname, 'certs/equifax.crt'),
      path.join(__dirname, '/x509.spec.js'),
      function (err) {
        expect(err.message).toMatch(/Error loading CA chain file/);
        done();
      }
    );
  });

  it('should throw an error "Failed to load cert"', (done) => {
    expect.hasAssertions();

    x509.verify(
      path.join(__dirname, '/x509.spec.js'),
      path.join(__dirname, 'chains/end-user-example.com.chain'),
      function (err) {
        expect(err.message).toMatch(/Failed to load cert/);
        done();
      }
    );
  });
});
