#pragma once

#include <filesystem>
#include <fstream>
#include <random>
#include <string>

// A directory under the system's temporary one, removed with everything in it when the
// test is done.
class TempDirectory {
 public:
  TempDirectory() {
    std::random_device random;
    _path = std::filesystem::temp_directory_path() / ("lugh-test-" + std::to_string(random()) + std::to_string(random()));
    std::filesystem::create_directories(_path);
  }

  ~TempDirectory() {
    std::error_code ignored;
    std::filesystem::remove_all(_path, ignored);
  }

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  const std::filesystem::path& path() const { return _path; }

  // Writes `content` to `relative`, making the directories it needs.
  std::filesystem::path write(const std::string& relative, const std::string& content) const {
    const auto file = _path / relative;
    std::filesystem::create_directories(file.parent_path());
    std::ofstream(file, std::ios::binary) << content;
    return file;
  }

 private:
  std::filesystem::path _path;
};
