#pragma once

#include "pro.h"
#include "bytes.hpp"
#include "segment.hpp"

#include <cstdint>
#include <exception>
#include <memory>

#include "cxx.h"

rust::String idalib_segm_name(const segment_t *s) {
  auto name = qstring();

  if (get_segm_name(&name, s) > 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

std::size_t idalib_segm_bytes(const segment_t *s, rust::Vec<rust::u8>& buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), s->start_ea, GMB_READALL); sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}

std::uint8_t idalib_segm_align(const segment_t *s) {
  return s->align;
}

std::uint8_t idalib_segm_bitness(const segment_t *s) {
  return s->bitness;
}

std::uint8_t idalib_segm_perm(const segment_t *s) {
  return s->perm;
}

std::uint8_t idalib_segm_type(const segment_t *s) {
  return s->type;
}

void idalib_segm_set_perm(segment_t *s, std::uint8_t perm) {
  if (s != nullptr) {
    s->perm = perm;
  }
}
