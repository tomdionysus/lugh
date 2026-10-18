// The command line parser: the input split on NUL into arguments. The smallest parser Lugh
// owns, and the one that proves the fuzz build works before the ones that matter arrive.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cli.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  std::vector<std::string> arguments{"lugh"};
  std::string current;
  for (std::size_t i = 0; i < size; ++i) {
    if (data[i] == 0) {
      arguments.push_back(current);
      current.clear();
    } else {
      current.push_back(static_cast<char>(data[i]));
    }
  }
  arguments.push_back(current);

  std::vector<char*> argv;
  for (auto& argument : arguments) argv.push_back(argument.data());

  const auto options = lugh::cli::parse(static_cast<int>(argv.size()), argv.data());
  (void)options;
  (void)lugh::cli::usage();
  return 0;
}
