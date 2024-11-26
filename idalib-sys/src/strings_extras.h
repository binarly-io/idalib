#pragma once

#include "strlist.hpp"

#include "cxx.h"

ea_t idalib_get_strlist_item(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.ea;
}
