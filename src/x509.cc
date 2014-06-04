#include <cstring>
#include <nan.h>
#include <x509.h>

using namespace v8;

// Field names that OpenSSL is missing.
static const char *MISSING[3][2] = {
  {
    "1.3.6.1.4.1.311.60.2.1.1",
    "jurisdictionOfIncorpationLocalityName"
  },

  {
    "1.3.6.1.4.1.311.60.2.1.2",
    "jurisdictionOfIncorporationStateOrProvinceName"
  },

  {
    "1.3.6.1.4.1.311.60.2.1.3",
    "jurisdictionOfIncorporationCountryName"
  }
};


Handle<Value> try_parse(const std::string& dataString);

std::string parse_args(_NAN_METHOD_ARGS) {
  if (args.Length() == 0) {
    NanThrowTypeError("Must provide a certificate string.");
    return std::string();
  }
  if (!args[0]->IsString()) {
    NanThrowTypeError("Certificate must be a string.");
    return std::string();
  }

  if (args[0]->ToString()->Length() == 0) {
    NanThrowTypeError("Certificate argument provided, but left blank.");
    return std::string();
  }
  
  return *String::Utf8Value(args[0]->ToString());
}

NAN_METHOD(get_altnames) {
  NanScope();
  std::string parsed_arg = parse_args(args);
  if(parsed_arg.size() == 0) {
    NanReturnUndefined();
  }

  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  NanReturnValue(exports->Get(NanNew<String>("altNames")));
}

NAN_METHOD(get_subject) {
  NanScope();
  std::string parsed_arg = parse_args(args);
  if(parsed_arg.size() == 0) {
    NanReturnUndefined();
  }

  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  NanReturnValue(exports->Get(NanNew<String>("subject")));
}

NAN_METHOD(get_issuer) {
  NanScope();
  std::string parsed_arg = parse_args(args);
  if(parsed_arg.size() == 0) {
    NanReturnUndefined();
  }

  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  NanReturnValue(exports->Get(NanNew<String>("issuer")));
}

NAN_METHOD(parse_cert) {
  NanScope();
  std::string parsed_arg = parse_args(args);
  if(parsed_arg.size() == 0) {
    NanReturnUndefined();
  }

  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  NanReturnValue(exports);
}

NAN_METHOD(parse_pem) {
  NanScope();
  std::string parsed_arg = parse_args(args);
  if(parsed_arg.size() == 0) {
    NanReturnUndefined();
  }

  Local<Object> exports(try_parse_pem(parsed_arg)->ToObject());
  NanReturnValue(exports);
}


void put_rsa_info_to_exports(Handle<Object>& exports, RSA* rsa) {
  char *public_exponent = BN_bn2hex(rsa->e);
  char *public_modulus = BN_bn2hex(rsa->n);
  if(public_exponent) {
    exports->Set(NanNew<String>("publicModulus"), NanNew<String>(public_exponent));
    OPENSSL_free(public_exponent);
  }
  if(public_modulus) {
    exports->Set(NanNew<String>("publicExponent"), NanNew<String>(public_modulus));
    OPENSSL_free(public_modulus);
  }
}

/*
 * This is where everything is handled for both -0.11.2 and 0.11.3+.
 */
Handle<Value> try_parse(const std::string& dataString) {
  NanEscapableScope();
  const char* data = dataString.c_str();
  
  Local<Object> exports(NanNew<Object>());
  X509 *cert;

  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    NanThrowError("BIO doesn't support BIO_puts.");
    BIO_free(bio);
    return NanEscapeScope(exports);
  }
  else if (result <= 0) {
    NanThrowError("No data was written to BIO.");
    BIO_free(bio);
    return NanEscapeScope(exports);
  }

  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
  if (cert == NULL) {
    BIO_free(bio);
    NanThrowError("Unable to parse certificate.");
    return NanEscapeScope(exports);
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
  

  exports->Set(NanNew<String>("subject"), parse_name(X509_get_subject_name(cert)));
  exports->Set(NanNew<String>("issuer"), parse_name(X509_get_issuer_name(cert)));
  exports->Set(NanNew<String>("serial"), parse_serial(X509_get_serialNumber(cert)));
  exports->Set(NanNew<String>("notBefore"), parse_date(X509_get_notBefore(cert)));
  exports->Set(NanNew<String>("notAfter"), parse_date(X509_get_notAfter(cert)));

  // get OCSP urls (if available)
  {
    Local<Array> ocspList = NanNew<Array>();
    STACK_OF(OPENSSL_STRING) *ocsplst;
    ocsplst = X509_get1_ocsp(cert);
    for (int j = 0; j < sk_OPENSSL_STRING_num(ocsplst); j++) {
      ocspList->Set(j, NanNew<String>(sk_OPENSSL_STRING_value(ocsplst, j)));
    }
    X509_email_free(ocsplst);

    exports->Set(NanNew<String>("ocspUrls"), ocspList);
  }


  Local<Array> altNames(NanNew<Array>());
  STACK_OF(GENERAL_NAME) *names = NULL;

  names = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
  if (names != NULL) {
    int length = sk_GENERAL_NAME_num(names);
    for (int i = 0; i < length; i++) {
      GENERAL_NAME *current = sk_GENERAL_NAME_value(names, i);

      if (current->type == GEN_DNS) {
        char *name = (char*) ASN1_STRING_data(current->d.dNSName);

        if (ASN1_STRING_length(current->d.dNSName) != (int) strlen(name)) {
          NanThrowError("Malformed alternative names field.");
          return NanEscapeScope(exports);
        }

        altNames->Set(i, NanNew<String>(name));
      }
      
    }
  }
  sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free); // http://stackoverflow.com/a/15876197/403571

  exports->Set(NanNew<String>("altNames"), altNames);

  X509_free(cert);
  BIO_free(bio);

  return NanEscapeScope(exports);
}

Handle<Value> parse_serial(ASN1_INTEGER *serial) {
  NanEscapableScope();
  Local<String> serialNumber;
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
  char *hex = BN_bn2hex(bn);

  serialNumber = NanNew<String>(hex);
  BN_free(bn);
  OPENSSL_free(hex);
  return NanEscapeScope(serialNumber);
}


Handle<Value> parse_date(ASN1_TIME *date) {
  NanEscapableScope();
  char formatted[64] = {0,};
  
  BIO *bio = BIO_new(BIO_s_mem());
  ASN1_TIME_print(bio, date);

  BUF_MEM *bm;
  BIO_get_mem_ptr (bio, &bm);
  BUF_strlcpy (formatted, bm->data, std::min(bm->length + 1, sizeof(formatted)-1));
  BIO_free (bio);
  Local<Value> args[1] = {
    NanNew<String>(formatted)
  };
  return NanEscapeScope(NanGetCurrentContext()->Global()->Get(NanNew<String>("Date"))->ToObject()->CallAsConstructor(1, args));
}

Handle<Object> parse_name(X509_NAME *subject) {
  NanEscapableScope();
  Local<Object> cert(NanNew<Object>());
  int i, length;
  ASN1_OBJECT *entry;
  unsigned char *value;
  char buf[255];
  length = X509_NAME_entry_count(subject);
  for (i = 0; i < length; i++) {
    entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i));
    OBJ_obj2txt(buf, 255, entry, 0);
    value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
    cert->Set(NanNew<String>(real_name(buf)), NanNew<String>((const char*) value));
  }
  return NanEscapeScope(cert);
}

// Fix for missing fields in OpenSSL.
const char* real_name(char *data) {
  int i, length = (int) sizeof(MISSING) / sizeof(MISSING[0]);

  for (i = 0; i < length; i++) {
    if (strcmp(data, MISSING[i][0]) == 0)
      return MISSING[i][1];
  }
  return data;
}

Handle<Value> try_parse_pem(const std::string& dataString) {
  NanEscapableScope();
  const char* data = dataString.c_str();

  Local<Object> exports(NanNew<Object>());
  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    NanThrowError("BIO doesn't support BIO_puts.");
    return NanEscapeScope(exports);
  }
  else if (result <= 0) {
    NanThrowError("No data was written to BIO.");
    return NanEscapeScope(exports);
  }

  RSA *private_key = NULL;

  private_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)"");
  if(private_key) {
    put_rsa_info_to_exports(exports, private_key);
    RSA_free(private_key);
  }

  BIO_free(bio);
  return NanEscapeScope(exports);
}
