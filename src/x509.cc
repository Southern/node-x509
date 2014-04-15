#include <cstring>
#include <nan.h>
#include <x509.h>

using namespace v8;

// Field names that OpenSSL is missing.
char *MISSING[3][2] = {
  {
    (char*) "1.3.6.1.4.1.311.60.2.1.1",
    (char*) "jurisdictionOfIncorpationLocalityName"
  },

  {
    (char*) "1.3.6.1.4.1.311.60.2.1.2",
    (char*) "jurisdictionOfIncorporationStateOrProvinceName"
  },

  {
    (char*) "1.3.6.1.4.1.311.60.2.1.3",
    (char*) "jurisdictionOfIncorporationCountryName"
  }
};


Handle<Value> try_parse(const std::string& dataString);

std::string parse_args(_NAN_METHOD_ARGS) {
  if (args.Length() == 0) {
    ThrowException(Exception::Error(String::New("Must provide a certificate file.")));
    return NULL;
  }

  if (!args[0]->IsString()) {
    ThrowException(Exception::TypeError(String::New("Certificate must be a string.")));
    return NULL;
  }

  if (args[0]->ToString()->Length() == 0) {
    ThrowException(Exception::TypeError(String::New("Certificate argument provided, but left blank.")));
    return NULL;
  }

  return *String::Utf8Value(args[0]->ToString());
}

NAN_METHOD(get_altnames) {
  NanScope();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  NanReturnValue(exports->Get(String::NewSymbol("altNames")));
}

NAN_METHOD(get_subject) {
  NanScope();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  NanReturnValue(exports->Get(String::NewSymbol("subject")));
}

NAN_METHOD(get_issuer) {
  NanScope();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  NanReturnValue(exports->Get(String::NewSymbol("issuer")));
}

NAN_METHOD(parse_cert) {
  NanScope();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  NanReturnValue(exports);
}

NAN_METHOD(parse_pem) {
  NanScope();
  Local<Object> exports(try_parse_pem(parse_args(args))->ToObject());
  NanReturnValue(exports);
}


void put_rsa_info_to_exports(Handle<Object>& exports, RSA* rsa) {
  char *public_exponent = BN_bn2hex(rsa->e);
  char *public_modulus = BN_bn2hex(rsa->n);
  if(public_exponent) {
    exports->Set(String::NewSymbol("publicModulus"), String::New(public_exponent));
    OPENSSL_free(public_exponent);
  }
  if(public_modulus) {
    exports->Set(String::NewSymbol("publicExponent"), String::New(public_modulus));
    OPENSSL_free(public_modulus);
  }
}

/*
 * This is where everything is handled for both -0.11.2 and 0.11.3+.
 */
Handle<Value> try_parse(const std::string& dataString) {
  NanScope();
  const char* data = dataString.c_str();
  
  Handle<Object> exports(Object::New());
  X509 *cert;

  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    ThrowException(Exception::Error(String::New("BIO doesn't support BIO_puts.")));
    BIO_free(bio);
    return scope.Close(exports);
  }
  else if (result <= 0) {
    ThrowException(Exception::Error(String::New("No data was written to BIO.")));
    BIO_free(bio);
    return scope.Close(exports);
  }

  // Try raw read
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

  if (cert == NULL) {
    BIO_free(bio);
    ThrowException(Exception::Error(String::New("Unable to parse certificate.")));
    return scope.Close(exports);
  }

  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if(pkey) {
    RSA *rsa_public_key = NULL;
    rsa_public_key = EVP_PKEY_get1_RSA(pkey);
    if(rsa_public_key) {
      put_rsa_info_to_exports(exports, rsa_public_key);
      RSA_free(rsa_public_key);
    }
    EVP_PKEY_free(pkey);
  }
  

  exports->Set(String::NewSymbol("subject"), parse_name(X509_get_subject_name(cert)));
  exports->Set(String::NewSymbol("issuer"), parse_name(X509_get_issuer_name(cert)));
  exports->Set(String::NewSymbol("serial"), parse_serial(X509_get_serialNumber(cert)));
  exports->Set(String::NewSymbol("notBefore"), parse_date((char*) ASN1_STRING_data(X509_get_notBefore(cert))));
  exports->Set(String::NewSymbol("notAfter"), parse_date((char*) ASN1_STRING_data(X509_get_notAfter(cert))));

  Local<Array> altNames(Array::New());
  STACK_OF(GENERAL_NAME) *names = NULL;
  int i;

  names = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

  if (names != NULL) {
    int length = sk_GENERAL_NAME_num(names);
    for (i = 0; i < length; i++) {
      GENERAL_NAME *current = sk_GENERAL_NAME_value(names, i);

      if (current->type == GEN_DNS) {
        char *name = (char*) ASN1_STRING_data(current->d.dNSName);

        if (ASN1_STRING_length(current->d.dNSName) != (int) strlen(name)) {
          ThrowException(Exception::Error(String::New("Malformed alternative names field.")));
          return scope.Close(exports);
        }

        altNames->Set(i, String::New(name));
      }
      
    }
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free); // http://stackoverflow.com/a/15876197/403571

  exports->Set(String::NewSymbol("altNames"), altNames);

  X509_free(cert);
  BIO_free(bio);
  return scope.Close(exports);
}

Handle<Value> parse_serial(ASN1_INTEGER *serial) {
  NanScope();
  Local<String> serialNumber;
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
  char *hex = BN_bn2hex(bn);

  serialNumber = String::New(hex);
  BN_free(bn);
  OPENSSL_free(hex);
  return scope.Close(serialNumber);
}

Handle<Value> parse_date(char *date) {
  NanScope();
  char current[3];
  int i;
  Local<Array> dateArray(Array::New());
  Local<String> output(String::New(""));
  Local<Value> args[1];

  for (i = 0; i < (int) strlen(date) - 1; i += 2) {
    strncpy(current, &date[i], 2);
    current[2] = '\0';

    dateArray->Set((i / 2), String::New(current));
  }

  output = String::Concat(output, String::Concat(dateArray->Get(1)->ToString(), String::New("/")));
  output = String::Concat(output, String::Concat(dateArray->Get(2)->ToString(), String::New("/")));
  output = String::Concat(output, String::Concat(String::New("20"), dateArray->Get(0)->ToString()));
  output = String::Concat(output, String::New(" "));
  output = String::Concat(output, String::Concat(dateArray->Get(3)->ToString(), String::New(":")));
  output = String::Concat(output, String::Concat(dateArray->Get(4)->ToString(), String::New(":")));
  output = String::Concat(output, String::Concat(dateArray->Get(5)->ToString(), String::New(" GMT")));
  args[0] = output;

  return scope.Close(Context::GetCurrent()->Global()->Get(String::New("Date"))->ToObject()->CallAsConstructor(1, args));
}

Handle<Object> parse_name(X509_NAME *subject) {
  NanScope();
  Handle<Object> cert(Object::New());
  int i, length;
  ASN1_OBJECT *entry;
  unsigned char *value;
  char buf[255];
  length = X509_NAME_entry_count(subject);
  for (i = 0; i < length; i++) {
    entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i));
    OBJ_obj2txt(buf, 255, entry, 0);
    value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
    cert->Set(String::NewSymbol(real_name(buf)), String::New((const char*) value));
  }
  return scope.Close(cert);
}

// Fix for missing fields in OpenSSL.
char* real_name(char *data) {
  int i, length = (int) sizeof(MISSING) / sizeof(MISSING[0]);

  for (i = 0; i < length; i++) {
    if (strcmp(data, MISSING[i][0]) == 0)
      return MISSING[i][1];
  }
  return data;
}

Handle<Value> try_parse_pem(const std::string& dataString) {
  NanScope();

  const char* data = dataString.c_str();

  Handle<Object> exports(Object::New());
  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    ThrowException(Exception::Error(String::New("BIO doesn't support BIO_puts.")));
    return scope.Close(exports);
  }
  else if (result <= 0) {
    ThrowException(Exception::Error(String::New("No data was written to BIO.")));
    return scope.Close(exports);
  }

  RSA *private_key = NULL;

  private_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)"");
  if(private_key) {
    put_rsa_info_to_exports(exports, private_key);
    RSA_free(private_key);
  }

  BIO_free(bio);
  return scope.Close(exports);
}
