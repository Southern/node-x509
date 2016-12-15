node-x509
=========

[![Build Status](https://travis-ci.org/Southern/node-x509.svg?branch=master)](https://travis-ci.org/Southern/node-x509)

Simple X509 certificate parser.

## Installation

From NPM *(recommended)*: `npm install x509`

Building and testing from source:
```
sudo npm install -g node-gyp
npm install
npm test
```

## Usage
Reading from a file:
```js
const x509 = require('x509');
var issuer = x509.getIssuer(__dirname + '/certs/your.crt');
```

Reading from a string:
```js
const fs = require('fs'),
      x509 = require('x509');
var issuer = x509.getIssuer(fs.readFileSync('./certs/your.crt').toString());
```

## Methods
**Notes:**
- `cert` may be a filename or a raw base64 encoded PEM string in any of these methods.

#### x509.getAltNames(`cert`)
Parse certificate with `x509.parseCert` and return the alternate names.

```js
const x509 = require('x509');
var altNames = x509.getAltNames(__dirname + '/certs/nodejitsu.com.crt');
/*
altNames = [ '*.nodejitsu.com', 'nodejitsu.com' ]
*/
```

#### x509.getIssuer(`cert`)
Parse certificate with `x509.parseCert` and return the issuer.

```js
const x509 = require('x509');
var issuer = x509.getIssuer(__dirname + '/certs/nodejitsu.com.crt');
/*
issuer = { countryName: 'GB',
  stateOrProvinceName: 'Greater Manchester',
  localityName: 'Salford',
  organizationName: 'COMODO CA Limited',
  commonName: 'COMODO High-Assurance Secure Server CA' }
*/
```

#### x509.getSubject(`cert`)
Parse certificate with `x509.parseCert` and return the subject.

```js
const x509 = require('x509');
var subject = x509.getSubject(__dirname + '/certs/nodejitsu.com.crt');
/*
subject = { countryName: 'US',
  postalCode: '10010',
  stateOrProvinceName: 'NY',
  localityName: 'New York',
  streetAddress: '902 Broadway, 4th Floor',
  organizationName: 'Nodejitsu',
  organizationalUnitName: 'PremiumSSL Wildcard',
  commonName: '*.nodejitsu.com' }
*/
```

#### x509.parseCert(`cert`)
Parse subject, issuer, valid before and after date, and alternate names from certificate.

```js
const x509 = require('x509');
var cert = x509.parseCert(__dirname + '/certs/nodejitsu.com.crt');
/*
cert = { subject:
   { countryName: 'US',
     postalCode: '10010',
     stateOrProvinceName: 'NY',
     localityName: 'New York',
     streetAddress: '902 Broadway, 4th Floor',
     organizationName: 'Nodejitsu',
     organizationalUnitName: 'PremiumSSL Wildcard',
     commonName: '*.nodejitsu.com' },
  issuer:
   { countryName: 'GB',
     stateOrProvinceName: 'Greater Manchester',
     localityName: 'Salford',
     organizationName: 'COMODO CA Limited',
     commonName: 'COMODO High-Assurance Secure Server CA' },
  notBefore: Sun Oct 28 2012 20:00:00 GMT-0400 (EDT),
  notAfter: Wed Nov 26 2014 18:59:59 GMT-0500 (EST),
  altNames: [ '*.nodejitsu.com', 'nodejitsu.com' ],
  signatureAlgorithm: 'sha1WithRSAEncryption',
  fingerPrint: 'E4:7E:24:8E:86:D2:BE:55:C0:4D:41:A1:C2:0E:06:96:56:B9:8E:EC',
  publicKey: {
    algorithm: 'rsaEncryption',
    e: '65537',
    n: '.......' } }
*/
```


#### x509.verify(`cert`, `CABundlePath`, function(err, result){ /*...*/})

Performs basic certificate validation against a bundle of ca certificates.

It accepts an error-first callback as first argument. If the error is null, then
the certificate is valid.

The error messages are the same returned by openssl: [x509_verify_cert_error_string](https://www.openssl.org/docs/man1.0.2/crypto/X509_STORE_CTX_get_error.html)


**Note:**
As now, this function only accepts absolute paths to existing files as arguments

```js
const x509 = require('x509');

x509.verify(
  __dirname + '/certs/user.com.crt',
  __dirname + 'enduser-example.com.chain',
  function(err, result){ /*...*/}
);

```

## Examples
Checking the date to make sure the certificate is active:
```js
const x509 = require('x509');
var cert = x509.parseCert('yourcert.crt'),
    date = new Date();

if (cert.notBefore > date) {
  // Certificate isn't active yet.
}
if (cert.notAfter < date) {
  // Certificate has expired.
}
```

## License

MIT

#### Alternative implementation / build issues
If you are suffering from hard to fix build issues, there is an alternative (pure javascript) implementation using emscripten: https://github.com/encharm/x509.js (based on node-x509, slightly different API)
