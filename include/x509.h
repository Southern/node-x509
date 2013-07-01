#ifndef __x509_h
#define __x509_h

#include <string>

// Include header for addon version, node/v8 inclusions, etc.
#include <addon.h>

// OpenSSL headers
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace v8;

// Custom X509_DATE struct. Default tm struct is a bit much to have to
// cast and recast in order to write/read with sprintf/printf.
typedef struct {
  char year[5];
  char day[3];
  char month[3];
  char hours[3];
  char minutes[3];
  char seconds[3];
} X509_DATE;

Handle<Value> get_altnames(const Arguments &args);
Handle<Value> get_subject(const Arguments &args);
Handle<Value> get_issuer(const Arguments &args);
Handle<Object> parse_cert(const Arguments &args);
Handle<String> parse_date(char *date);
Handle<Object> parse_name(X509_NAME *subject);
Handle<Value> public_parse_cert(const Arguments &args);

#endif
