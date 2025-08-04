#pragma once

#include "idalib.hpp"
#include "name.hpp"

bool idalib_get_library_version(int *major, int *minor, int *build) {
  return get_library_version(*major, *minor, *build);
}

bool idalib_set_name(uval_t ea, const char *name, int flags) {
  if (name == nullptr) {
    return false;
  }
  return set_name(ea, name, flags);
}
