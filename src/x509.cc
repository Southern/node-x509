#include <cstring>
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

/*
 * This is where everything is handled for both -0.11.2 and 0.11.3+.
 */
Handle<Value> try_parse(const std::string& dataString) {
  NanEscapableScope();
  const char* data = dataString.c_str();

  Handle<Object> exports(NanNew<Object>());
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

  // Try raw read
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

  if (cert == NULL) {
    // Switch to file BIO
    bio = BIO_new(BIO_s_file());

    // If raw read fails, try reading the input as a filename.
    if (!BIO_read_filename(bio, data)) {
      NanThrowError("File doesn't exist.");
      return NanEscapeScope(exports);
    }

    // Try reading the bio again with the file in it.
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (cert == NULL) {
      NanThrowError("Unable to parse certificate.");
      return NanEscapeScope(exports);
    }
  }

  exports->Set(NanNew<String>("version"), NanNew<Integer>((int) X509_get_version(cert)));
  exports->Set(NanNew<String>("subject"), parse_name(X509_get_subject_name(cert)));
  exports->Set(NanNew<String>("issuer"), parse_name(X509_get_issuer_name(cert)));
  exports->Set(NanNew<String>("serial"), parse_serial(X509_get_serialNumber(cert)));
  exports->Set(NanNew<String>("notBefore"), parse_date(X509_get_notBefore(cert)));
  exports->Set(NanNew<String>("notAfter"), parse_date(X509_get_notAfter(cert)));

  // Signature Algorithm
  int sig_alg_nid = OBJ_obj2nid(cert->sig_alg->algorithm);
  if (sig_alg_nid == NID_undef) {
    NanThrowError("unable to find specified signature algorithm name.");
    return NanEscapeScope(exports);
  }
  exports->Set(NanNew<String>("signatureAlgorithm"), NanNew<String>(OBJ_nid2ln(sig_alg_nid)));

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
    exports->Set(NanNew<String>("fingerPrint"), NanNew<String>(fingerprint));
  }

  // public key
  int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (pkey_nid == NID_undef) {
    NanThrowError("unable to find specified public key algorithm name.");
    return NanEscapeScope(exports);
  }
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  Local<Object> publicKey = NanNew<Object>();
  publicKey->Set(NanNew<String>("algorithm"), NanNew<String>(OBJ_nid2ln(pkey_nid)));

  if (pkey_nid == NID_rsaEncryption) {
    char *rsa_e_dec, *rsa_n_hex;
    RSA *rsa_key;
    rsa_key = pkey->pkey.rsa;
    rsa_e_dec = BN_bn2dec(rsa_key->e);
    rsa_n_hex = BN_bn2hex(rsa_key->n);
    publicKey->Set(NanNew<String>("e"), NanNew<String>(rsa_e_dec));
    publicKey->Set(NanNew<String>("n"), NanNew<String>(rsa_n_hex));
  }
  exports->Set(NanNew<String>("publicKey"), publicKey);
  EVP_PKEY_free(pkey);

  // alt names
  Local<Array> altNames(NanNew<Array>());
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
          NanThrowError("Malformed alternative names field.");
          return NanEscapeScope(exports);
        }

        altNames->Set(i, NanNew<String>(name));
      }
    }
  }
  exports->Set(NanNew<String>("altNames"), altNames);

  // Extensions
  Local<Object> extensions(NanNew<Object>());
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

    // remove newlines
    int lastchar = bptr->length;
    if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
      bptr->data[lastchar-1] = (char) 0;
    }
    if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
      bptr->data[lastchar] = (char) 0;
    }
    BIO_free(ext_bio);

    unsigned nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
      char extname[100];
      OBJ_obj2txt(extname, 100, (const ASN1_OBJECT *) obj, 1);
      extensions->Set(NanNew<String>(extname), NanNew<String>(bptr->data));
    } else {
      const char *c_ext_name = OBJ_nid2ln(nid);
      // IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
      extensions->Set(NanNew<String>(c_ext_name), NanNew<String>(bptr->data));
    }
  }
  exports->Set(NanNew<String>("extensions"), extensions);

  X509_free(cert);
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
  args[0] = NanNew<String>(formatted);

  return NanEscapeScope(NanGetCurrentContext()->Global()->Get(NanNew<String>("Date"))->ToObject()->CallAsConstructor(1, args));
}

Handle<Object> parse_name(X509_NAME *subject) {
  NanEscapableScope();
  Handle<Object> cert(NanNew<Object>());
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
