#pragma once

#include "ida/pro.h"
#include "ida/idp.hpp"

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
