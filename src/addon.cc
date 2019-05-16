#include <cstdlib>
#include <cstdio>

#include <addon.h>
#include <x509.h>

using namespace v8;

void init(Local<Object> exports) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  v8::Local<v8::Context> context = isolate->GetCurrentContext();
  v8::HandleScope handle_scope(isolate);
  Nan::Set(exports,
    Nan::New<String>("version").ToLocalChecked(),
    Nan::New<String>(VERSION).ToLocalChecked());

  {
    v8::Local<v8::Function> method;
    Nan::New<FunctionTemplate>(verify)->GetFunction(context).ToLocal<v8::Function>(&method);
    Nan::Set(exports,
      Nan::New<String>("verify").ToLocalChecked(),
      method
    );
  }

  {
    v8::Local<v8::Function> method;
    Nan::New<FunctionTemplate>(get_altnames)->GetFunction(context).ToLocal<v8::Function>(&method);
    Nan::Set(exports,
      Nan::New<String>("getAltNames").ToLocalChecked(),
      method
    );
  }
  {
    v8::Local<v8::Function> method;
    Nan::New<FunctionTemplate>(get_subject)->GetFunction(context).ToLocal<v8::Function>(&method);
    Nan::Set(exports,
      Nan::New<String>("getSubject").ToLocalChecked(),
      method
    );
  }
  {
    v8::Local<v8::Function> method;
    Nan::New<FunctionTemplate>(get_issuer)->GetFunction(context).ToLocal<v8::Function>(&method);
    Nan::Set(exports,
      Nan::New<String>("getIssuer").ToLocalChecked(),
      method
    );
  }
  {
    v8::Local<v8::Function> method;
    Nan::New<FunctionTemplate>(parse_cert)->GetFunction(context).ToLocal<v8::Function>(&method);
    Nan::Set(exports,
      Nan::New<String>("parseCert").ToLocalChecked(),
      method
    );
  }
}

NODE_MODULE(x509, init)
