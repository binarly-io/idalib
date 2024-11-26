#pragma once

#include "strlist.hpp"
#include "kernwin.hpp"

#include "cxx.h"

ea_t idalib_get_strlist_item_addr(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.ea;
}

int idalib_get_strlist_item_length(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.length;
}

int idalib_get_strlist_item_type(size_t n) {
  string_info_t si;
  get_strlist_item(&si, n);
  return si.type;
}

rust::String idalib_ea2str(ea_t ea) {
  auto out = qstring();

  if (ea2str(&out, ea)) {
    return rust::String(out.c_str());
  } else {
    return rust::String();
  }
}
