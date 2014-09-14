#include <cstdlib>
#include <cstdio>

#include <addon.h>
#include <x509.h>

using namespace v8;

void init(Handle<Object> exports) {
  exports->Set(NanNew<String>("version"), NanNew<String>(VERSION));
  exports->Set(NanNew<String>("getAltNames"), NanNew<FunctionTemplate>(get_altnames)->GetFunction());
  exports->Set(NanNew<String>("getSubject"), NanNew<FunctionTemplate>(get_subject)->GetFunction());
  exports->Set(NanNew<String>("getIssuer"), NanNew<FunctionTemplate>(get_issuer)->GetFunction());
  exports->Set(NanNew<String>("parseCert"), NanNew<FunctionTemplate>(parse_cert)->GetFunction());
}

NODE_MODULE(x509, init)
