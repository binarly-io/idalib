#pragma once

#include "search.hpp"

#include "cxx.h"

ea_t idalib_find_text(ea_t start_ea, const char *text) {
  return find_text(start_ea, 0, 0, text, SEARCH_DOWN);
}

ea_t idalib_find_defined(ea_t start_ea) {
  return find_defined(start_ea, SEARCH_DOWN);
}
