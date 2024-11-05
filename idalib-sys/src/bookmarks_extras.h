#pragma once

#include "moves.hpp"

#include "cxx.h"

rust::u32 idalib_bookmarks_t_mark(ea_t ea, uint32 index, const char *desc) {
  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_mark(e, index, nullptr, desc, nullptr);
}

rust::String idalib_bookmarks_t_get_desc(uint32 index) {
  auto desc = qstring();
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  if (bookmarks_t_get_desc(&desc, e, index, nullptr) != 0) {
    return rust::String(desc.c_str());
  } else {
    return rust::String();
  }
}

bool idalib_bookmarks_t_erase(uint32 index) {
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_erase(e, index, nullptr);
}

rust::u32 idalib_bookmarks_t_find_index(ea_t ea) {
  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_find_index(e, nullptr);
}

rust::u32 idalib_bookmarks_t_size(void) {
  ea_t ea = 0;

  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_size(e, nullptr);
}
