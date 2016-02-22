#ifndef __addon_h
#define __addon_h

#include <node.h>
#include <v8.h>

using namespace v8;

void init(Local<Object> exports);

#endif
