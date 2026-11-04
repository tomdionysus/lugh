//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <filesystem>
#include <fstream>
#include <string>

#include "dannan/test/fixtures/temp_dir.h"

// Dannan's TempDir, under the build tree and removed when the test is done, with a way to
// put a file in it.
class TempDirectory : public dannan::test::TempDir {
 public:
  // Writes `content` to `relative`, making the directories it needs.
  std::filesystem::path write(const std::string& relative, const std::string& content) const {
    const auto file = path() / relative;
    std::filesystem::create_directories(file.parent_path());
    std::ofstream(file, std::ios::binary) << content;
    return file;
  }
};
