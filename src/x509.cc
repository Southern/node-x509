#include <cstring>
#include <x509.h>

using namespace v8;

// Field names that OpenSSL is missing.
static const char *MISSING[4][2] = {
  {
    "1.2.840.113533.7.65.0",
    "entrustVersionInfo"
  },
  
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

std::string parse_args(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() == 0) {
    Nan::ThrowTypeError("Must provide a certificate string.");
    return std::string();
  }

  if (!info[0]->IsString()) {
    Nan::ThrowTypeError("Certificate must be a string.");
    return std::string();
  }

  if (info[0]->ToString()->Length() == 0) {
    Nan::ThrowTypeError("Certificate argument provided, but left blank.");
    return std::string();
  }

  return *String::Utf8Value(info[0]->ToString());
}

NAN_METHOD(get_altnames) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  Local<Value> key = Nan::New<String>("altNames").ToLocalChecked();
  info.GetReturnValue().Set(
    Nan::Get(exports, key).ToLocalChecked());
}

NAN_METHOD(get_subject) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  Local<Value> key = Nan::New<String>("subject").ToLocalChecked();
  info.GetReturnValue().Set(
    Nan::Get(exports, key).ToLocalChecked());
}

NAN_METHOD(get_issuer) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  Local<Value> key = Nan::New<String>("issuer").ToLocalChecked();
  info.GetReturnValue().Set(
    Nan::Get(exports, key).ToLocalChecked());
}

NAN_METHOD(parse_cert) {
  Nan::HandleScope scope;
  std::string parsed_arg = parse_args(info);
  if(parsed_arg.size() == 0) {
    info.GetReturnValue().SetUndefined();
  }
  Local<Object> exports(try_parse(parsed_arg)->ToObject());
  info.GetReturnValue().Set(exports);
}

/*
 * This is where everything is handled for both -0.11.2 and 0.11.3+.
 */
Handle<Value> try_parse(const std::string& dataString) {
  Nan::EscapableHandleScope scope;
  const char* data = dataString.c_str();

  Local<Object> exports = Nan::New<Object>();
  X509 *cert;

  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    Nan::ThrowError("BIO doesn't support BIO_puts.");
    BIO_free(bio);
    return scope.Escape(exports);
  }
  else if (result <= 0) {
    Nan::ThrowError("No data was written to BIO.");
    BIO_free(bio);
    return scope.Escape(exports);
  }

  // Try raw read
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

  if (cert == NULL) {
    // Switch to file BIO
    bio = BIO_new(BIO_s_file());

    // If raw read fails, try reading the input as a filename.
    if (!BIO_read_filename(bio, data)) {
      Nan::ThrowError("File doesn't exist.");
      return scope.Escape(exports);
    }

    // Try reading the bio again with the file in it.
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (cert == NULL) {
      Nan::ThrowError("Unable to parse certificate.");
      return scope.Escape(exports);
    }
  }

  Nan::Set(exports, 
    Nan::New<String>("version").ToLocalChecked(), 
    Nan::New<Integer>((int) X509_get_version(cert)));
  Nan::Set(exports, 
    Nan::New<String>("subject").ToLocalChecked(), 
    parse_name(X509_get_subject_name(cert)));
  Nan::Set(exports, 
    Nan::New<String>("issuer").ToLocalChecked(), 
    parse_name(X509_get_issuer_name(cert)));
  Nan::Set(exports, 
    Nan::New<String>("serial").ToLocalChecked(), 
    parse_serial(X509_get_serialNumber(cert)));
  Nan::Set(exports, 
    Nan::New<String>("notBefore").ToLocalChecked(), 
    parse_date(X509_get_notBefore(cert)));
  Nan::Set(exports, 
    Nan::New<String>("notAfter").ToLocalChecked(), 
    parse_date(X509_get_notAfter(cert)));

  // Signature Algorithm
  int sig_alg_nid = OBJ_obj2nid(cert->sig_alg->algorithm);
  if (sig_alg_nid == NID_undef) {
    Nan::ThrowError("unable to find specified signature algorithm name.");
    return scope.Escape(exports);
  }
  Nan::Set(exports,
    Nan::New<String>("signatureAlgorithm").ToLocalChecked(),
    Nan::New<String>(OBJ_nid2ln(sig_alg_nid)).ToLocalChecked());

  // fingerPrint
  unsigned int md_size, idx;
  unsigned char md[EVP_MAX_MD_SIZE];
  if (X509_digest(cert, EVP_sha1(), md, &md_size)) {
    const char hex[] = "0123456789ABCDEF";
    char fingerprint[EVP_MAX_MD_SIZE * 3];
    for (idx = 0; idx < md_size; idx++) {
      fingerprint[3*idx] = hex[(md[idx] & 0xf0) >> 4];
      fingerprint[(3*idx)+1] = hex[(md[idx] & 0x0f)];
      fingerprint[(3*idx)+2] = ':';
    }

    if (md_size > 0) {
      fingerprint[(3*(md_size-1))+2] = '\0';
    } else {
      fingerprint[0] = '\0';
    }
    Nan::Set(exports, 
      Nan::New<String>("fingerPrint").ToLocalChecked(), 
      Nan::New<String>(fingerprint).ToLocalChecked());
  }

  // public key
  int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (pkey_nid == NID_undef) {
    Nan::ThrowError("unable to find specified public key algorithm name.");
    return scope.Escape(exports);
  }
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  Local<Object> publicKey = Nan::New<Object>();
  Nan::Set(publicKey, 
    Nan::New<String>("algorithm").ToLocalChecked(), 
    Nan::New<String>(OBJ_nid2ln(pkey_nid)).ToLocalChecked());

  if (pkey_nid == NID_rsaEncryption) {
    char *rsa_e_dec, *rsa_n_hex;
    RSA *rsa_key;
    rsa_key = pkey->pkey.rsa;
    rsa_e_dec = BN_bn2dec(rsa_key->e);
    rsa_n_hex = BN_bn2hex(rsa_key->n);
    Nan::Set(publicKey, 
      Nan::New<String>("e").ToLocalChecked(), 
      Nan::New<String>(rsa_e_dec).ToLocalChecked());
    Nan::Set(publicKey, 
      Nan::New<String>("n").ToLocalChecked(), 
      Nan::New<String>(rsa_n_hex).ToLocalChecked());
  }
  Nan::Set(exports, Nan::New<String>("publicKey").ToLocalChecked(), publicKey);
  EVP_PKEY_free(pkey);

  // alt names
  Local<Array> altNames(Nan::New<Array>());
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
          Nan::ThrowError("Malformed alternative names field.");
          return scope.Escape(exports);
        }
        Nan::Set(altNames, i, Nan::New<String>(name).ToLocalChecked());
      }
    }
  }
  Nan::Set(exports, Nan::New<String>("altNames").ToLocalChecked(), altNames);

  // Extensions
  Local<Object> extensions(Nan::New<Object>());
  STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
  int num_of_exts;
  int index_of_exts;
  if (exts) {
    num_of_exts = sk_X509_EXTENSION_num(exts);
  } else {
    num_of_exts = 0;
  }

  // IFNEG_FAIL(num_of_exts, "error parsing number of X509v3 extensions.");

  for (index_of_exts = 0; index_of_exts < num_of_exts; index_of_exts++) {
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, index_of_exts);
    // IFNULL_FAIL(ext, "unable to extract extension from stack");
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
    // IFNULL_FAIL(obj, "unable to extract ASN1 object from extension");

    BIO *ext_bio = BIO_new(BIO_s_mem());
    // IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
    if (!X509V3_EXT_print(ext_bio, ext, 0, 0)) {
      M_ASN1_OCTET_STRING_print(ext_bio, ext->value);
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_NOCLOSE);

    char *data = (char*) malloc(bptr->length + 1);
    BUF_strlcpy(data, bptr->data, bptr->length + 1);
    data = trim(data, bptr->length);

    BIO_free(ext_bio);

    unsigned nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
      char extname[100];
      OBJ_obj2txt(extname, 100, (const ASN1_OBJECT *) obj, 1);
      Nan::Set(extensions, 
        Nan::New<String>(real_name(extname)).ToLocalChecked(), 
        Nan::New<String>(data).ToLocalChecked());

    } else {
      const char *c_ext_name = OBJ_nid2ln(nid);
      // IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
      Nan::Set(extensions,
        Nan::New<String>(real_name((char*)c_ext_name)).ToLocalChecked(), 
        Nan::New<String>(data).ToLocalChecked());
    }
  }
  Nan::Set(exports,
    Nan::New<String>("extensions").ToLocalChecked(), extensions);

  X509_free(cert);
  BIO_free(bio);
  
  return scope.Escape(exports);
}

Handle<Value> parse_serial(ASN1_INTEGER *serial) {
  Nan::EscapableHandleScope scope;
  Local<String> serialNumber;
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
  char *hex = BN_bn2hex(bn);

  serialNumber = Nan::New<String>(hex).ToLocalChecked();
  BN_free(bn);
  OPENSSL_free(hex);
  return scope.Escape(serialNumber);
}

Handle<Value> parse_date(ASN1_TIME *date) {
  Nan::EscapableHandleScope scope;
  BIO *bio;
  BUF_MEM *bm;
  char formatted[64];
  Local<Value> args[1];

  formatted[0] = '\0';
  bio = BIO_new(BIO_s_mem());
  ASN1_TIME_print(bio, date);
  BIO_get_mem_ptr(bio, &bm);
  BUF_strlcpy(formatted, bm->data, bm->length + 1);
  BIO_free(bio);
  args[0] = Nan::New<String>(formatted).ToLocalChecked();

  Local<Object> global = Nan::GetCurrentContext()->Global();
  Local<Object> DateObject = Nan::Get(global, 
    Nan::New<String>("Date").ToLocalChecked()).ToLocalChecked()->ToObject();
  return scope.Escape(DateObject->CallAsConstructor(1, args));
}

Handle<Object> parse_name(X509_NAME *subject) {
  Nan::EscapableHandleScope scope;
  Local<Object> cert = Nan::New<Object>();
  int i, length;
  ASN1_OBJECT *entry;
  unsigned char *value;
  char buf[255];
  length = X509_NAME_entry_count(subject);
  for (i = 0; i < length; i++) {
    entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i));
    OBJ_obj2txt(buf, 255, entry, 0);
    value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
    Nan::Set(cert,
      Nan::New<String>(real_name(buf)).ToLocalChecked(),
      Nan::New<String>((const char*) value).ToLocalChecked());
  }
  return scope.Escape(cert);
}

// Fix for missing fields in OpenSSL.
char* real_name(char *data) {
  int i, length = (int) sizeof(MISSING) / sizeof(MISSING[0]);

  for (i = 0; i < length; i++) {
    if (strcmp(data, MISSING[i][0]) == 0)
      return (char*) MISSING[i][1];
  }

  return data;
}

char* trim(char *data, int len) {
  if (data[0] == '\n' || data[0] == '\r') {
    data = data+1;
  }
  else if (len > 1 && (data[len-1] == '\n' || data[len-1] == '\r')) {
    data[len-1] = (char) 0;
  }
  else if (len > 0 && (data[len] == '\n' || data[len] == '\r')) {
    data[len] = (char) 0;
  }
  else {
    return data;
  }

  return trim(data, len - 1);
}
