#include <cstdlib>
#include <cstdio>

#include <addon.h>
#include <x509.h>

using namespace v8;

void init(Handle<Object> exports) {
  exports->Set(NanSymbol("version"), NanNew<String>(VERSION));
  exports->Set(NanSymbol("getAltNames"), NanNew<FunctionTemplate>(get_altnames)->GetFunction());
  exports->Set(NanSymbol("getSubject"), NanNew<FunctionTemplate>(get_subject)->GetFunction());
  exports->Set(NanSymbol("getIssuer"), NanNew<FunctionTemplate>(get_issuer)->GetFunction());
  exports->Set(NanSymbol("parseCert"), NanNew<FunctionTemplate>(parse_cert)->GetFunction());
  exports->Set(NanSymbol("parsePem"), NanNew<FunctionTemplate>(parse_pem)->GetFunction());
}

NODE_MODULE(x509, init)
