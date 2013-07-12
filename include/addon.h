#ifndef __addon_h
#define __addon_h

#include <cstdlib>
#include <cstdio>

#include <node.h>
#include <v8.h>

using namespace v8;

void init(Handle<Object> exports);

#endif
