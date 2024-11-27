#pragma once

#include "strlist.hpp"

#include "cxx.h"

ea_t idalib_get_strlist_item_addr(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.ea;
}

size_t idalib_get_strlist_item_length(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return (size_t)si.length;
}
