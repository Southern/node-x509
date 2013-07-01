#include <x509.h>

using namespace v8;

Handle<Value> get_altnames(const Arguments &args) {
  HandleScope scope;
  Handle<Object> exports(parse_cert(args));

  return scope.Close(exports->Get(String::NewSymbol("altNames")));
}

Handle<Value> get_subject(const Arguments &args) {
  HandleScope scope;
  Handle<Object> exports(parse_cert(args));

  return scope.Close(exports->Get(String::NewSymbol("subject")));
}

Handle<Value> get_issuer(const Arguments &args) {
  HandleScope scope;
  Handle<Object> exports(parse_cert(args));

  return scope.Close(exports->Get(String::NewSymbol("issuer")));
}

// Where everything is actually handled
Handle<Object> parse_cert(const Arguments &args) {
  HandleScope scope;
  Handle<Object> exports(Object::New());
  X509 *cert;

  if (args.Length() == 0) {
    ThrowException(Exception::Error(String::New("Must provide a certificate file.")));
    return scope.Close(exports);
  }

  if (!args[0]->IsString()) {
    ThrowException(Exception::TypeError(String::New("Certificate must be a string.")));
    return scope.Close(exports);
  }

  if (args[0]->ToString()->Length() == 0) {
    ThrowException(Exception::TypeError(String::New("Certificate argument provided, but left blank.")));
    return scope.Close(exports);
  }

  String::Utf8Value value(args[0]);
  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, *value);

  if (result == -2) {
    ThrowException(Exception::Error(String::New("BIO doesn't support BIO_puts.")));
    return scope.Close(exports);
  }
  else if (result <= 0) {
    ThrowException(Exception::Error(String::New("No data was written to BIO.")));
    return scope.Close(exports);
  }

  // Try raw read
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

  if (cert == NULL) {
    // Switch to file BIO
    bio = BIO_new(BIO_s_file());

    // If raw read fails, try reading the input as a filename.
    if (!BIO_read_filename(bio, *value)) {
      ThrowException(Exception::Error(String::New("File doesn't exist.")));
      return scope.Close(exports);
    }

    // Try reading the bio again with the file in it.
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (cert == NULL) {
      ThrowException(Exception::Error(String::New("Unable to parse certificate.")));
      return scope.Close(exports);
    }
  }

  exports->Set(String::NewSymbol("subject"), parse_name(X509_get_subject_name(cert)));
  exports->Set(String::NewSymbol("issuer"), parse_name(X509_get_issuer_name(cert)));
  exports->Set(String::NewSymbol("notBefore"), parse_date((char*) ASN1_STRING_data(X509_get_notBefore(cert))));
  exports->Set(String::NewSymbol("notAfter"), parse_date((char*) ASN1_STRING_data(X509_get_notAfter(cert))));

  Handle<Array> altNames(Array::New());
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

  exports->Set(String::NewSymbol("altNames"), altNames);

  return scope.Close(exports);
}

Handle<String> parse_date(char *date) {
  HandleScope scope;
  char current[5];
  char *theDate = (char*) malloc(sizeof(char) * 30);
  X509_DATE *xdate = (X509_DATE*) malloc(sizeof(X509_DATE));
  int i;

  for (i = 0; i < (int) strlen(date) - 1; i += 2) {
    strncpy(current, &date[i], 2);

    switch (i) {
      case 0:
        sprintf(xdate->year, "%s", current);
        break;

      case 2:
        sprintf(xdate->month, "%s", current);
        break;

      case 4:
        sprintf(xdate->day, "%s", current);
        break;

      case 6:
        sprintf(xdate->hours, "%s", current);
        break;

      case 8:
        sprintf(xdate->minutes, "%s", current);
        break;

      case 10:
        sprintf(xdate->seconds, "%s", current);
        break;
    }
  }

  sprintf(theDate, "%s/%s/20%s %s:%s:%s GMT", xdate->month, xdate->day, xdate->year, xdate->hours, xdate->minutes, xdate->seconds);

  free(xdate);
  free(theDate);

  return scope.Close(String::New(theDate));
}

Handle<Object> parse_name(X509_NAME *subject) {
  HandleScope scope;
  Handle<Object> cert(Object::New());
  int i, nid, length;
  ASN1_OBJECT *entry;
  unsigned char *value;
  char buf[255];
  length = X509_NAME_entry_count(subject);
  for (i = 0; i < length; i++) {
    entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i));
    nid = OBJ_obj2txt(buf, 255, entry, 0);
    value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
    cert->Set(String::NewSymbol(buf), String::New((const char*) value));
  }
  return scope.Close(cert);
}

Handle<Value> public_parse_cert(const Arguments &args) {
  HandleScope scope;

  return scope.Close(parse_cert(args));
}
