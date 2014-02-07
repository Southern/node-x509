var x509 = require('../build/Release/x509'),
    fs = require('fs'),
    path = require('path'),
    assert = require('assert');

// All cert files should read without throwing an error.
// Simple enough test, no?
fs.readdirSync(path.join(__dirname, 'certs')).filter(function(file) {
  return file.match(/\.crt$/);
}).forEach(function (file) {
  console.log("File: %s", file);
  console.log(x509.parseCert(path.join(__dirname, 'certs', file)));
  console.log();
});

//console.log(x509.parseCert(path.join(__dirname, 'certs', 'cert.crt')));
var parsedCertificate = (x509.parseCert(
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

// TODO
// currently below does not work, the password is 'test'
var parsedPrivateEncrypted = x509.parsePem(
'-----BEGIN ENCRYPTED PRIVATE KEY-----\n' +
'MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIy6mIG5Vb46ACAggA\n' +
'MBQGCCqGSIb3DQMHBAhRLEl72yxGTwSCBMj1t9adt4Db5a8sSNTR2nVE6gBHmjG2\n' +
's3lzG8/wyftic5x4hhHQirV7wxVa3GWSF4tJ/sG/z533zKBM3pFtQPNRtURBQFRU\n' +
'fZUyF9fC2KVYZiyRX9GaRJ2LzK74ZtPc0Dk5k+mfXYGlTPtp6OIm9+Y7ZkTIs3Qr\n' +
'Jh+N1CJB01za9epSVCtEm51QLSFwGbIvIeEYGFnnSqBxUKHp8XCzCNQz1a/vQe4y\n' +
'hgY687XHkpt8dmqVGBt7AWkUS0cM7ZvhFeLfr0wonJzOU+Ik9npsFdlmU4n0mqLp\n' +
'6BOSMyxMQD9nsEFfHEjWQJijlaErb/XY1CkwC/ZQEylcO7rYGXPsLbvVRzSmn28d\n' +
'LlnApHBxMl33d7l3XWL9LteIIfPHPINly5LbIZUrj3UyWudkM/FP4ukXl12OQ2Bh\n' +
'3/SDtoYSjoRtiDLYiDFkngofCURJSyS41pnOR3p6WAXNTMVySkpgGTN85H+5+5gc\n' +
'kHAKARF40ssqB587KUn/o2llgy0Ml7NhlCx0Af6HerSsntk/cCXfO1ic66/3U8/i\n' +
'O67Fm6ZDfc4HLKPazpif3VEElhoOMJV+v/ZvBzQ2u/s2UqHdJGDnIsIbrFD482+e\n' +
'ntzd4x/dg6rXgnl3pliNgHEp+g5BWaJDzJTZaTgtyksYWluvwHLEd8qx60Q+IufX\n' +
'Brk1Pc26MYJIHfXWTjx+PHKcaVudBcGzGW7XVphqSgNlcFw8NR8FMxNIWO482ijr\n' +
'OEkkmeNSn+WRF57TA3u8w5pgh7ayyceQQ/cYOgTzlnLAFWRAzTmrq76vLGyZI5Zn\n' +
'yI1yeStmdU/05jGO0DIiwqPoIE+L413/QugbbOK+D7T/vyV9EZ6HHpmgtn8lR9sx\n' +
'kZ0QJmLqE6DeKFlfwrPzSA91sDTgpSA3mGuL/hlbaxaT8JFWJGJ03yuMG9Aiu/aj\n' +
'mvzqTfku4Mby6/4E7DWlj6HSRFTXZAJsWlUYLPvSuUsWebhpbD/9rzts4tqWMcxF\n' +
'SPEORecdXABYud+0JeNF6ziNd58cqGRKsO1F4ph35WzRXJSQ1Qo3wFjbxk49jeco\n' +
'TEQUDmw8V2kprfXyL91e8LYQDHjzMA3FGw7I3Xbg4beRkUg8uV11jcIf5m9+TTcS\n' +
'bpA2L2XdJKdZ4/Sph62rnByVqWgG8Xv1fEfpXmD19wx5qxVFeeb3NKvDt9FoZgdM\n' +
'vUiZYuCC6KDIjURg/YqSDVaLAdVeO6abnsuZZsj927I56o4f0WdXc1poRWUmrBBK\n' +
'JAe5AgJpu9ls0+51IrvWJJ99YjRLCEgIZdEe3qMTKp1DQQwS4YDEPi7AAMpVg7GX\n' +
'D3twY+I+0HSA8lKTOdmGzl7CL28fuVxr/i8YW976kcL26XMXILqTcd1KbyGFK5VK\n' +
'1y8WYuRxSySKpII1kDS3fKmwKNWgTsDB0YqzizZ7o8oSn4oWv/PrYmVzdz3yPmTC\n' +
'UIUJ15Y1yVyTyqgt/BNb9EPrkSjDWlr4WGuwgBrJUEvbAFHN46T54LL7FRTPbWyr\n' +
'HSoXxfePtim6TI+UtQJdFObOOQobb/DuAg5QFuv8Lq86CAyRTIDZcYqbGQSoIdLM\n' +
'rgfZhl2IAlFQOtdOylmHP8Yldx5auCfi/nn+xL1qou4T3+EUdxjyz1CVteAILaSg\n' +
'cto=\n' +
'-----END ENCRYPTED PRIVATE KEY-----\n',
'test');

assert(parsedCertificate.publicModulus == parsedPrivate.publicModulus &&
  parsedCertificate.publicExponent == parsedPrivate.publicExponent,
  "Modulus and exponents should be equal");