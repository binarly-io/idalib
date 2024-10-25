#pragma once

#include "ida/bytes.hpp"

#include "cxx.h"

rust::String idalib_get_cmt(ea_t ea, bool rptble) {
  auto cmt = qstring();

  if (get_cmt(&cmt, ea, rptble) != 0) {
    return rust::String(cmt.c_str());
  } else {
    return rust::String();
  }
}
