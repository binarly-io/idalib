#pragma once

#include "pro.h"
#include "entry.hpp"

#include "cxx.h"

rust::String idalib_entry_name(uval_t ord) {
  auto name = qstring();

  if (get_entry_name(&name, ord) != 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}
