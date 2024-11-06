#pragma once

#include "pro.h"
#include "kernwin.hpp"
#include "auto.hpp"

#include <cstdint>

struct license_manager_t;
struct license_manager_t_vtbl;

struct license_result_t {
  uint64_t v0;
  uint32_t is_ok;
};

struct borrow_arg3 {
  int a;
  int16_t b;
  int64_t c;
};

struct license_manager_t_vtbl {
  void *_skip_a[4];
  int (*borrow_license)(license_manager_t *, void *, borrow_arg3 *, int64_t, void **);
  void *(*get_field_ptr)(license_manager_t *);
  void *_skip_b[5];
  license_result_t *(*check)(license_manager_t *, bool *, int);
};

struct license_manager_t {
  license_manager_t_vtbl *_vtbl;
};

extern "C" license_manager_t *get_license_manager();

bool try_check_ida_license() {
  auto manager = get_license_manager();
  if (!manager) {
    return false;
  }

  auto res = manager->_vtbl->check(manager, 0, 0);
  if (res && res->is_ok) {
    return true;
  }

  auto field_ptr = manager->_vtbl->get_field_ptr(manager);
  borrow_arg3 borrow_license_arg3 = { 0, 0, 0x100000001LL };
  void *ptr = nullptr;

  auto nres = manager->_vtbl->borrow_license(manager, field_ptr, &borrow_license_arg3, 16, &ptr);

  if (ptr) {
    qfree(ptr);
  }

  return !nres;
}

int open_database_quiet(const char *name, bool auto_analysis) {
  // first check the license...
  if (!try_check_ida_license()) {
    return -1;
  }

  auto new_file = 0;
  const char *argv[] = { "idalib", name };
  auto result = init_database(2, argv, &new_file);

  if (result != 0) {
    return result;
  }

  (*callui)(ui_notification_t::ui_ready_to_run);

  if (auto_analysis) {
    result = !auto_wait();
  }

  return result;
}
