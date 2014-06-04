
var x509 = require('../build/Release/x509'),
    fs = require('fs'),
    path = require('path'),
    assert = require('chai').assert;
require('mocha');


var parsedCertificate;

describe('CRT file parsing', function() {

  fs.readdirSync(path.join(__dirname, 'certs')).filter(function(file) {
    return file.match(/\.crt$/);
  }).forEach(function (file) {

    it('should parse ' + file, function() {

      var content = fs.readFileSync(path.join(__dirname, 'certs', file), 'utf8');
      var contentJson = fs.readFileSync(path.join(__dirname, 'certs', file + '.json'), 'utf8');

      assert.deepEqual(
        JSON.parse(JSON.stringify(x509.parseCert(content))),
        JSON.parse(contentJson));
    });
  });
  it('should parse inline private key', function() {
    parsedCertificate = (x509.parseCert(
      '-----BEGIN CERTIFICATE-----\n' +
      'MIIDXTCCAkWgAwIBAgIJAPv5luejZzgwMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n' +
      'BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n' +
      'aWRnaXRzIFB0eSBMdGQwHhcNMTQwMjAyMjA0OTEwWhcNMTQwMzA0MjA0OTEwWjBF\n' +
      'MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\n' +
      'ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n' +
      'CgKCAQEA5sW8hM95zG7bGh9+0M4576QTOVwFWIZgWrZuLeHAsxyNHBL0Nv0iLBZ9\n' +
      '3kSSj3L3Lf6eVCD9BZWDbUehY8xZocRErujA6c47ilPS/NVppK2jjVN+NULIH4h1\n' +
      'OOa2qVPYKtxhULiLCelh5FHXIYlQAqBiik9zh+PZnteOBayU9WQGmNgzvFGM71oh\n' +
      'krL1j7eb1vH0mfpgPJo9tK2O9uq0Bx0ly8KkH5zIuh1HuRNarlPtR5sA8JxAtGBy\n' +
      'dP6kWF5h1UHbKXM283PfHbVprUHRfRoE767XqZOPZRxxqpnAxNS/tjR8zpBGmxKi\n' +
      'PwS90y20Bm2yLnV9VycrrWSFqfYdHQIDAQABo1AwTjAdBgNVHQ4EFgQUMGCMgAHj\n' +
      'oN/jOUW1UkgmymubfUIwHwYDVR0jBBgwFoAUMGCMgAHjoN/jOUW1UkgmymubfUIw\n' +
      'DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAfPqjVJv21ZTERVzyt/K0\n' +
      '9d4cuIJh2pJsknIVq/6g80A1BOyi+V7mwcEG5PPGRyWYNa+RDhW93okjbiqiakVk\n' +
      'HKLX8l4yMh67MD7HAsgsZhYXyibgJqfNyUysntD930BN4gzobTV6/L4E8YSnvr/V\n' +
      'pnGBheCzRht3nDBSTo0OZkaUEyhw+T1P/MHPEIzPqXrs/9jrDRRHsZgZ4dYJm6Sy\n' +
      'F8KWmYVYKO/WnexRh2MsppbbMjrhd1hmpI/XeTaaqfLi5NLKPfCBFfmKHxXB81sK\n' +
      'UYukVVhwbAjngarYBzbPBzNTsKXWCNzYDUbblhsvjVfOf8kxsdIUc5ulNNimYjNa\n' +
      '5A==\n' +
      '-----END CERTIFICATE-----\n'
    ));
  });
  it('should throw exception on invalid certificate', function() {
    try {
      x509.parseCert('dupa');
      assert.fail('exception should have been thrown');
    } catch(err) {
      assert(err.message === 'Unable to parse certificate.', 'message should be appropriate');
    }
  });
  it('should throw exception on missing argument', function() {
    try {
      x509.parseCert();
      assert.fail('exception should have been thrown');
    } catch(err) {
      assert(err.message === 'Must provide a certificate string.', 'message should be appropriate');
    }
  });
  it('should throw exception on bad type', function() {
    try {
      x509.parseCert(3298);
      assert.fail('exception should have been thrown');
    } catch(err) {
      assert(err.message === 'Certificate must be a string.', 'message should be appropriate');
    }
  });
  it('should throw exception on zero length', function() {
    try {
      x509.parseCert("");
      assert.fail('exception should have been thrown');
    } catch(err) {
      assert(err.message === 'Certificate argument provided, but left blank.', 'message should be appropriate');
    }
  });

});


describe('PEM file parsing', function() {
  it('should parse private key matching to public key', function() {


    var parsedPrivate = x509.parsePem('-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEpAIBAAKCAQEA5sW8hM95zG7bGh9+0M4576QTOVwFWIZgWrZuLeHAsxyNHBL0\n' +
    'Nv0iLBZ93kSSj3L3Lf6eVCD9BZWDbUehY8xZocRErujA6c47ilPS/NVppK2jjVN+\n' +
    'NULIH4h1OOa2qVPYKtxhULiLCelh5FHXIYlQAqBiik9zh+PZnteOBayU9WQGmNgz\n' +
    'vFGM71ohkrL1j7eb1vH0mfpgPJo9tK2O9uq0Bx0ly8KkH5zIuh1HuRNarlPtR5sA\n' +
    '8JxAtGBydP6kWF5h1UHbKXM283PfHbVprUHRfRoE767XqZOPZRxxqpnAxNS/tjR8\n' +
    'zpBGmxKiPwS90y20Bm2yLnV9VycrrWSFqfYdHQIDAQABAoIBAQC97tL48BYLxtV3\n' +
    'y6JBUupmLMFRvUX9FSPqpSlLg/losUAGcicjtvVQGfbgX8nMXM/JwD0perkkxmiU\n' +
    'IZdYHxFKTdJFrvVPuVhRwintw+weCHeK0sQWK++v3Ey2V1TRSluo8xb5K9nrf3T9\n' +
    'SMpqJKyAbOaNdVTd7A7pZ/nQ+7jhuTAZlW1SnjJ2mkOML5UbM7Ncf7X92tfC/KNQ\n' +
    'afxW4VHxyNLDN5m9Qjq42Tlela+kFEJr7yosd7OLsH7XoiOnPHV1qYO7zrLxNfJe\n' +
    'xyP3RwkbSmAJ8h8oJcZn69gP8URr/KW/B++3pHPkQVQglk+pZRogtpD89JgCUn25\n' +
    'PHNukxqBAoGBAP6dMOn4xVvQj/aLjfvDlfM4XIU3vNiEItYhs8z99PwBYfqlAdLd\n' +
    '8uNTCLBH6GBeW1zbvKRGz5bZiERTNe+8lPilzVWVd183yRMXWHIzMDBA7FpSJlRV\n' +
    'Ci5UiI6ICHR24OsJ+CN+ctPDNpg9wNtRe1ppM6a8+9zqI0tArkfE1FUhAoGBAOgH\n' +
    'UlaN7HdW/Vb/l7/WyZK15DkJx057v2WTZYdTV2sN6h1Jrsq7NOx7xNntJmk0x/Ad\n' +
    'uKOx99V/h308EWjgwa+IEduiAt0GgRXhWItn9mUWD2YlhcYmOXidyYrBDq3JyZUM\n' +
    'Ts7DEc8CV0Fs8okRVq02f7H2Z+oUvDqyYkLV6wx9AoGAc0zfz7R2O0PRTcaYv4As\n' +
    'sX2+eB1riWkdFXchox0GCfDeW9DJaKJV0ZfSgXGuy6UvHnfrj0D51Mghqz87V5tA\n' +
    'ovECcVVEP3xVtC2IQf7oPZHI9oXpEZuJBr4FMPZtTcBfzlAvbHNgsIDggkTExwy5\n' +
    'HZIyb7l5HOtynCtoQNvjg8ECgYEAvIuOjgUf/U3z6akin+IixJQH042tpooKWrku\n' +
    'zIudwsF417nTTqxXcj+VE92Q0/bu7aDJNEPe9199MvgH0aip20B/+nCpUQADD0uh\n' +
    'zw54+2W0t7WQAhd3phrZ9mWwzunlY7evpnZ/Vy84xlKIt3cebvyVQYDQqjeVSUFB\n' +
    'dbwtF2UCgYB/y+osTUFNxDqu7FX8HBlL7F3ZBjjFUs8xpZZuZKWG+7CCcSE/rPdw\n' +
    'E5sHwC0OxTWnRaiNaP5TEV/u95p9cZYQNIgrzl1ooU5ZFzl7NX6VnJfQAyA/WeCB\n' +
    '3MvNt068tqRoQpL3btfzyn7kGweDdZ0w181Y9Wyfg1Pb4tKWbZrCBw==\n' +
    '-----END RSA PRIVATE KEY-----\n'
    );
    assert.deepEqual(parsedPrivate,
      { publicModulus: '010001',
      publicExponent: 'E6C5BC84CF79CC6EDB1A1F7ED0CE39EFA413395C055886605AB66E2DE1C0B31C8D1C12F436FD222C167DDE44928F72F72DFE9E5420FD0595836D47A163CC59A1C444AEE8C0E9CE3B8A53D2FCD569A4ADA38D537E3542C81F887538E6B6A953D82ADC6150B88B09E961E451D721895002A0628A4F7387E3D99ED78E05AC94F5640698D833BC518CEF5A2192B2F58FB79BD6F1F499FA603C9A3DB4AD8EF6EAB4071D25CBC2A41F9CC8BA1D47B9135AAE53ED479B00F09C40B4607274FEA4585E61D541DB297336F373DF1DB569AD41D17D1A04EFAED7A9938F651C71AA99C0C4D4BFB6347CCE90469B12A23F04BDD32DB4066DB22E757D57272BAD6485A9F61D1D' });
    assert(parsedCertificate.publicModulus == parsedPrivate.publicModulus &&
      parsedCertificate.publicExponent == parsedPrivate.publicExponent,
      "Modulus and exponents should be equal");
  });
});


