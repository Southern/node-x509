#ifndef __x509_h
#define __x509_h

// Include header for addon version, node/v8 inclusions, etc.
#include <addon.h>
#include <node_version.h>
#include <nan.h>

// OpenSSL headers
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

using namespace v8;

NAN_METHOD(get_altnames);
NAN_METHOD(get_subject);
NAN_METHOD(get_issuer);
NAN_METHOD(get_issuer);
NAN_METHOD(parse_cert);
NAN_METHOD(parse_pem);


Handle<Value> try_parse(const std::string& dataString);
Handle<Value> try_parse_pem(const std::string& dataString);
Handle<Value> parse_date(const char *date);
Handle<Value> parse_serial(ASN1_INTEGER *serial);
Handle<Object> parse_name(X509_NAME *subject);
char* real_name(char *data);

#endif
