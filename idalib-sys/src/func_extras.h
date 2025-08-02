#pragma once

#include "pro.h"
#include "funcs.hpp"
#include "gdl.hpp"
#include "name.hpp"

#include <cstdint>
#include <exception>
#include <memory>

#include "cxx.h"

uint64_t idalib_func_flags(const func_t *f) {
  return f == nullptr ? 0 : f->flags;
}

rust::String idalib_func_name(const func_t *f) {
  auto name = qstring();

  if (get_func_name(&name, f->start_ea) != 0) {
    return rust::String(name.c_str());
  } else {
    return rust::String();
  }
}

std::unique_ptr<qflow_chart_t> idalib_func_flow_chart(func_t *f, int fc_options) {
  if (auto cfg = std::make_unique<qflow_chart_t>(nullptr, f, BADADDR, BADADDR, fc_options); cfg != nullptr) {
    return cfg;
  }
  throw std::runtime_error("cannot build function flow chart");
}

const qbasic_block_t *idalib_qflow_graph_getn_block(const qflow_chart_t *cfg, size_t n) {
  return n < std::size(cfg->blocks) ? &cfg->blocks[n] : nullptr;
}

rust::Slice<const int> idalib_qbasic_block_succs(qbasic_block_t const *blk) {
  return rust::Slice(std::begin(blk->succ), std::size(blk->succ));
}

rust::Slice<const int> idalib_qbasic_block_preds(qbasic_block_t const *blk) {
  return rust::Slice(std::begin(blk->pred), std::size(blk->pred));
}

bool idalib_func_set_name(const func_t *f, const char *name, int flags) {
  if (f == nullptr || name == nullptr) {
    return false;
  }
  return set_name(f->start_ea, name, flags);
}

void idalib_func_set_noret(func_t *f, bool noret) {
  if (f != nullptr) {
    if (noret) {
      f->flags |= FUNC_NORET;
    } else {
      f->flags &= ~FUNC_NORET;
    }
  }
}
