#pragma once

#include "ida/pro.h"
#include "ida/hexrays.hpp"
#include "ida/lines.hpp"

#include <sstream>

#include "cxx.h"

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) {
    return *f;
}

rust::String idalib_hexrays_cfunc_pseudocode(cfunc_t *f) {
  auto sv = f->get_pseudocode();
  auto sb = std::stringstream();

  auto buf = qstring();

  for (int i = 0; i < sv.size(); i++) {
    tag_remove(&buf, sv[i].line);
    sb << buf.c_str() << '\n';
  }

  return rust::String(sb.str());
}
