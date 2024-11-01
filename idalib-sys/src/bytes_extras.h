#pragma once

#include "bytes.hpp"

#include "cxx.h"

std::uint8_t idalib_get_byte(ea_t ea) { return get_byte(ea); }
std::uint16_t idalib_get_word(ea_t ea) { return get_word(ea); }
std::uint32_t idalib_get_dword(ea_t ea) { return get_dword(ea); }
std::uint64_t idalib_get_qword(ea_t ea) { return get_qword(ea); }

std::size_t idalib_get_bytes(ea_t ea, rust::Vec<rust::u8> &buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), ea, GMB_READALL);
      sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}
