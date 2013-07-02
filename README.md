node-x509
=========

Simple X509 certificate parser.

## Usage
Reading from a file:
```js
var x509 = require('x509');

var issuer = x509.getIssuer(__dirname + '/certs/your.crt');
```

Reading from a string:
```js
var fs = require('fs'),
    x509 = require('x509');

var issuer = x509.getIssuer(fs.readFileSync('./certs/your.crt').toString());
```

## Methods
**Notes:**
- `cert` may be a filename or a raw base64 encoded PEM string in any of these methods.


#### x509.getAltNames(`cert`)
Parse certificate with `x509.parseCert` and return the alternate names.

```js
var x509 = require('x509');

var altNames = x509.getAltNames(__dirname + '/certs/nodejitsu.com.crt');
/*
altNames = [ '*.nodejitsu.com', 'nodejitsu.com' ]
*/
```

#### x509.getIssuer(`cert`)
Parse certificate with `x509.parseCert` and return the issuer.

```js
var x509 = require('x509');

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
var x509 = require('x509');

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
var x509 = require('x509');

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
  notBefore: '10/29/2012 00:00:00 GMT',
  notAfter: '11/26/2014 23:59:59 GMT',
  altNames: [ '*.nodejitsu.com', 'nodejitsu.com' ] }
*/
```