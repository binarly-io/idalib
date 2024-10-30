#pragma once

#include "ida/moves.hpp"

#include "cxx.h"

rust::u32 idalib_bookmarks_t_size(ea_t ea) {
  idaplace_t ipl(ea, 0);
  renderer_info_t rinfo;
  rinfo.rtype = TCCRT_FLAT;
  rinfo.pos.cx = 0;
  rinfo.pos.cy = 5;
  lochist_entry_t e(&ipl, rinfo);

  return bookmarks_t_size(e, nullptr);
}
