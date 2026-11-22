//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/fuzz/target.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>

namespace lugh::fuzz {

std::vector<Bytes> corpus(const std::string& name) {
  const std::filesystem::path directory = std::filesystem::path(LUGH_FUZZ_CORPUS) / name;
  std::vector<std::filesystem::path> files;
  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
    if (entry.is_regular_file()) files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());

  std::vector<Bytes> out;
  for (const auto& file : files) {
    std::ifstream in(file, std::ios::binary);
    out.emplace_back(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  return out;
}

}  // namespace lugh::fuzz
