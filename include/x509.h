#ifndef __x509_h
#define __x509_h

#include <cstring>

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

Handle<Value> get_altnames(const Arguments &args);
Handle<Value> get_subject(const Arguments &args);
Handle<Value> get_issuer(const Arguments &args);
Handle<Object> parse_cert(const Arguments &args);
Handle<String> parse_date(char *date);
Handle<Object> parse_name(X509_NAME *subject);
Handle<Value> public_parse_cert(const Arguments &args);

#endif
