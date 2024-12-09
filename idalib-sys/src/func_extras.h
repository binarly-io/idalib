#pragma once

#include "pro.h"
#include "frame.hpp"
#include "funcs.hpp"
#include "gdl.hpp"
#include "typeinf.hpp"

#include <cstdint>
#include <exception>
#include <memory>

#include "cxx.h"

#ifndef CXXBRIDGE1_STRUCT_func_var_t
#define CXXBRIDGE1_STRUCT_func_var_t
struct func_var_t final {
  ::rust::String name;
  ::std::int64_t fp_offset;
  ::std::size_t size;

  ::std::uint32_t attributes;
  ::std::uint8_t alignment;
  int effective_alignment;

  // TODO: type...

  using IsRelocatable = ::std::true_type;

  func_var_t(const udm_t& m, const func_t *f);
};
#endif // CXXBRIDGE1_STRUCT_func_var_t

#ifndef CXXBRIDGE1_STRUCT_func_frame_t
#define CXXBRIDGE1_STRUCT_func_frame_t
struct func_frame_t final {
  ::rust::Vec<func_var_t> arguments;
  ::rust::Vec<func_var_t> locals;

  func_var_t saved_registers;
  func_var_t return_address;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_func_frame_t


func_var_t::func_var_t(const udm_t& m, const func_t *f) {
    auto offset = m.offset / 8;

    if (!m.name.empty()) {
      this->name = rust::String(m.name.c_str());
    }

    this->attributes = m.tafld_bits;
    this->alignment = m.fda;
    this->effective_alignment = m.effalign;

    this->fp_offset = soff_to_fpoff(const_cast<func_t *>(f), offset);
    this->size = m.size / 8;
}

void idalib_func_frame(const func_t *f, func_frame_t &fframe) {
  auto udt = udt_type_data_t();
  auto frame = tinfo_t();

  if (!frame.get_func_frame(f)) {
    throw std::runtime_error("cannot build function frame");
  }

  if (!frame.get_udt_details(&udt)) {
    throw std::runtime_error("cannot build function frame");
  }

  auto arguments_offset = frame_off_args(f);

  for (const auto &m : udt) {
    if (m.is_special_member()) {
      if (m.is_retaddr()) {
        fframe.return_address = func_var_t(m, f);
      } else if (m.is_savregs()) {
        fframe.saved_registers = func_var_t(m, f);
      }
      continue;
    }

    auto fvar = func_var_t(m, f);

    if ((m.offset / 8) < arguments_offset) {
      fframe.locals.push_back(std::move(fvar));
    } else {
      fframe.arguments.push_back(std::move(fvar));
    }
  }
}

std::int64_t idalib_func_spd(const func_t *f, ea_t ea) {
  return get_spd(const_cast<func_t *>(f), ea);
}

std::int64_t idalib_func_effective_spd(const func_t *f, ea_t ea) {
  return get_effective_spd(const_cast<func_t *>(f), ea);
}

std::int64_t idalib_func_sp_delta(const func_t *f, ea_t ea) {
  return get_sp_delta(const_cast<func_t *>(f), ea);
}

std::uint64_t idalib_func_flags(const func_t *f) {
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
