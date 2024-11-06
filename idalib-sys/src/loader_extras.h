#pragma once

#include "loader.hpp"

#include <cstdint>

#include "cxx.h"

uint64_t idalib_plugin_version(const plugin_t *p) {
  return p == nullptr ? 0 : p->version;
}

uint64_t idalib_plugin_flags(const plugin_t *p) {
  return p == nullptr ? 0 : p->flags;
}
