#pragma once

#include <optional>
#include <string>

#include "core/secret.h"
#include "core/task.h"

namespace lugh::system {

// The person at the terminal, from outside: the one way a passphrase reaches Lugh.
class Console {
 public:
  virtual ~Console() = default;

  // One line, typed without echo when there is a terminal, or read from standard input when
  // there is not, without its line ending. The prompt goes to standard error. nullopt at the
  // end of input, or past 1024 characters. Awaited: a person may take their time.
  virtual Task<std::optional<Secret>> read_secret(std::string prompt) = 0;

  // A secret for the person to copy down, on standard error, never through the logger: the
  // one thing Lugh ever shows that it will not show again.
  virtual void show_secret(const std::string& label, const Secret& secret) = 0;
};

}  // namespace lugh::system
