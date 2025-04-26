#pragma once

#include "pro.h"
#include "idp.hpp"
#include "segregs.hpp"

#include "cxx.h"

std::int32_t idalib_ph_id(const processor_t *ph) {
  return ph->id;
}

rust::String idalib_ph_short_name(const processor_t *ph) {
  auto name = ph->psnames[const_cast<processor_t *>(ph)->get_proc_index()];
  return rust::String(name);
}

rust::String idalib_ph_long_name(const processor_t *ph) {
  auto name = ph->plnames[const_cast<processor_t *>(ph)->get_proc_index()];
  return rust::String(name);
}

bool idalib_is_thumb_at(const processor_t *ph, ea_t ea) {
  const auto T = 20;

  if (ph->id == PLFM_ARM && !inf_is_64bit()) {
    auto tbit = get_sreg(ea, T);
    return tbit != 0 && tbit != BADSEL;
  }
  return false;
}
