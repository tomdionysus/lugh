//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "system/console.h"

namespace lugh::system {

// Standard input and error, with echo off while a secret is typed. Reading waits on a
// person, so it runs on `blocking` while the caller is suspended.
class SystemConsole : public Console {
 public:
  explicit SystemConsole(Executor blocking) : _blocking(std::move(blocking)) {}

  Task<std::optional<Secret>> read_secret(std::string prompt) override;
  void show_secret(const std::string& label, const Secret& secret) override;

 private:
  Executor _blocking;
};

}  // namespace lugh::system
