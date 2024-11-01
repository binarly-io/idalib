#pragma once

#include "pro.h"
#include "kernwin.hpp"
#include "auto.hpp"

int open_database_quiet(const char *name, bool auto_analysis) {
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
