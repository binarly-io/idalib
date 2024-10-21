#pragma once

#include "ida/hexrays.hpp"
#include "ida/lines.hpp"
#include "ida/pro.h"

#include <cstdint>
#include <memory>
#include <sstream>

#include "cxx.h"

struct cblock_iter {
  qlist<cinsn_t>::iterator start;
  qlist<cinsn_t>::iterator end;

  cblock_iter(cblock_t *b) : start(b->begin()), end(b->end()) {}
};

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) { return *f; }

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

std::unique_ptr<cblock_iter> idalib_hexrays_cblock_iter(cblock_t *b) {
  return std::unique_ptr<cblock_iter>(new cblock_iter(b));
}

cinsn_t *idalib_hexrays_cblock_iter_next(cblock_iter &it) {
  if (it.start != it.end) {
    return &*(it.start++);
  }
  return nullptr;
}

std::size_t idalib_hexrays_cblock_len(cblock_t *b) {
  return b->size();
}
