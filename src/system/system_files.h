#pragma once

#include "system/files.h"

namespace lugh::system {

// POSIX files: open with O_NOFOLLOW, fsync, rename, and link for a write that must not
// replace. A regular file has no readiness to wait on, on macOS or on Linux short of
// io_uring, so each call runs on `blocking`, a pool kept for it, while the caller is
// suspended; it is the one place Lugh's threads wait on a disk.
class SystemFiles : public Files {
 public:
  explicit SystemFiles(Executor blocking) : _blocking(std::move(blocking)) {}

  Task<bool> exists(std::string path) const override;
  Task<Result<Bytes>> read(std::string path, std::size_t most) const override;
  Task<Result<SecureBytes>> read_secret(std::string path, std::size_t most) const override;
  Task<Status> write(std::string path, Bytes data, bool replace) override;
  Task<Status> append(std::string path, Bytes data) override;
  Task<Status> truncate(std::string path, std::uint64_t size) override;
  Task<Status> remove(std::string path) override;
  Task<Status> make_directory(std::string path) override;

 private:
  Executor _blocking;
};

}  // namespace lugh::system
