#pragma once

#include "search.hpp"

#include "cxx.h"

ea_t idalib_find_text(ea_t start_ea, const char *text) {
  return find_text(start_ea, 0, 0, text, SEARCH_DOWN | SEARCH_NEXT);
}

ea_t idalib_find_imm(ea_t start_ea, uint32 imm) {
  return find_imm(start_ea, SEARCH_DOWN | SEARCH_NEXT, imm, nullptr);
}

ea_t idalib_find_defined(ea_t start_ea) {
  return find_defined(start_ea, SEARCH_DOWN | SEARCH_NEXT);
}
