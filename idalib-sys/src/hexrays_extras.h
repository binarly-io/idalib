#pragma once

#include "ida/pro.h"
#include "ida/hexrays.hpp"

#include "cxx.h"

cfunc_t *idalib_hexrays_cfuncptr_inner(const cfuncptr_t *f) {
    // return f->ptr;
    return *f;
}
