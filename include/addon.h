#ifndef __addon_h
#define __addon_h

#define VERSION "0.0.1"

#include <cstdlib>
#include <cstdio>

#include <node.h>
#include <v8.h>

using namespace v8;

void init(Handle<Object> exports);
Handle<Value> setupExports(Handle<Object> exports);

#endif
