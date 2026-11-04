//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/system/system_files.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <system_error>

#include "dannan/identity/durable_file.h"

namespace lugh::system {

namespace {

std::string reason() { return std::strerror(errno); }

class Descriptor {
 public:
  explicit Descriptor(int fd) : _fd(fd) {}
  ~Descriptor() {
    if (_fd >= 0) ::close(_fd);
  }
  Descriptor(const Descriptor&) = delete;
  Descriptor& operator=(const Descriptor&) = delete;

  int get() const { return _fd; }
  bool valid() const { return _fd >= 0; }

  int release() {
    const int fd = _fd;
    _fd = -1;
    return fd;
  }

 private:
  int _fd;
};

template <typename Buffer>
Result<Buffer> read_all(const std::string& path, std::size_t most) {
  using Answer = Result<Buffer>;

  Descriptor fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.valid()) {
    if (errno == ELOOP) return Answer::failure(path + " is a symlink, which is not followed");
    return Answer::failure("cannot read " + path + ": " + reason());
  }

  struct stat status{};
  if (::fstat(fd.get(), &status) != 0) return Answer::failure("cannot read " + path + ": " + reason());
  if (!S_ISREG(status.st_mode)) return Answer::failure(path + " is not a file");
  if (static_cast<std::size_t>(status.st_size) > most) return Answer::failure(path + " is larger than " + std::to_string(most) + " bytes");

  Buffer out(static_cast<std::size_t>(status.st_size));
  std::size_t done = 0;
  while (done < out.size()) {
    const auto got = ::read(fd.get(), out.data() + done, out.size() - done);
    if (got < 0 && errno == EINTR) continue;
    if (got < 0) return Answer::failure("cannot read " + path + ": " + reason());
    if (got == 0) break;
    done += static_cast<std::size_t>(got);
  }
  out.resize(done);

  // Grown since fstat: refused rather than read past the limit.
  unsigned char extra = 0;
  if (::read(fd.get(), &extra, 1) > 0) return Answer::failure(path + " changed while it was read");

  return Answer::success(std::move(out));
}

Status sync(int fd, const std::string& path) {
  int done = 0;
  do {
    done = ::fsync(fd);
  } while (done != 0 && errno == EINTR);
  if (done != 0) return Status::failure("cannot sync " + path + ": " + reason());
  return Status::success();
}

std::string directory_of(const std::string& path) {
  const auto parent = std::filesystem::path(path).parent_path().string();
  return parent.empty() ? std::string(".") : parent;
}

Status sync_directory(const std::string& directory) {
  Descriptor fd(::open(directory.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY));
  if (!fd.valid()) return Status::failure("cannot open " + directory + " to sync it: " + reason());
  if (::fsync(fd.get()) != 0) return Status::failure("cannot sync " + directory + ": " + reason());
  return Status::success();
}

bool exists_now(const std::string& path) {
  struct stat status{};
  return ::lstat(path.c_str(), &status) == 0;
}

// Dannan's durable writes (dannan/identity/durable_file.h): a temporary beside the file,
// synced, moved into place, the directory synced, owner-only. Creating refuses an existing
// file atomically, so of two inits racing exactly one makes the keyring.
Status write_now(const std::string& path, std::span<const unsigned char> data, bool replace) {
  const std::string_view contents(reinterpret_cast<const char*>(data.data()), data.size());
  try {
    if (replace) {
      dannan::identity::durable_replace_file(path, contents);
    } else {
      dannan::identity::durable_create_file(path, contents);
    }
    return Status::success();
  } catch (const std::filesystem::filesystem_error& e) {
    if (e.code() == std::errc::file_exists) return Status::failure(path + " exists, and is not replaced");
    return Status::failure("cannot write " + path + ": " + e.what());
  } catch (const std::exception& e) {
    return Status::failure("cannot write " + path + ": " + e.what());
  }
}

Status append_now(const std::string& path, std::span<const unsigned char> data) {
  Descriptor fd(::open(path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.valid()) return Status::failure("cannot append to " + path + ": " + reason());

  std::size_t done = 0;
  while (done < data.size()) {
    const auto put = ::write(fd.get(), data.data() + done, data.size() - done);
    if (put < 0 && errno == EINTR) continue;
    if (put <= 0) return Status::failure("cannot append to " + path + ": " + reason());
    done += static_cast<std::size_t>(put);
  }
  return sync(fd.get(), path);
}

Status truncate_now(const std::string& path, std::uint64_t size) {
  Descriptor fd(::open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.valid()) return Status::failure("cannot truncate " + path + ": " + reason());
  if (::ftruncate(fd.get(), static_cast<off_t>(size)) != 0) return Status::failure("cannot truncate " + path + ": " + reason());
  return sync(fd.get(), path);
}

Status remove_now(const std::string& path) {
  if (::unlink(path.c_str()) != 0) {
    if (errno == ENOENT) return Status::success();
    return Status::failure("cannot remove " + path + ": " + reason());
  }
  return sync_directory(directory_of(path));
}

Status make_directory_now(const std::string& path) {
  std::error_code ec;
  if (std::filesystem::is_directory(path, ec)) return Status::success();

  const auto parent = std::filesystem::path(path).parent_path();
  if (!parent.empty() && parent != path) {
    if (const auto made = make_directory_now(parent.string()); !made.ok) return made;
  }

  if (::mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) return Status::failure("cannot make " + path + ": " + reason());
  if (!std::filesystem::is_directory(path, ec)) return Status::failure(path + " is not a directory");
  return Status::success();
}

}  // namespace

// Each runs the blocking call on the pool; the arguments move into the work, so they live
// as long as it does.

Task<bool> SystemFiles::exists(std::string path) const {
  co_return co_await offload(_blocking, [path = std::move(path)] { return exists_now(path); });
}

Task<Result<Bytes>> SystemFiles::read(std::string path, std::size_t most) const {
  co_return co_await offload(_blocking, [path = std::move(path), most] { return read_all<Bytes>(path, most); });
}

Task<Result<SecureBuffer>> SystemFiles::read_secret(std::string path, std::size_t most) const {
  co_return co_await offload(_blocking, [path = std::move(path), most] { return read_all<SecureBuffer>(path, most); });
}

Task<Status> SystemFiles::write(std::string path, Bytes data, bool replace) {
  co_return co_await offload(_blocking, [path = std::move(path), data = std::move(data), replace] { return write_now(path, data, replace); });
}

Task<Status> SystemFiles::append(std::string path, Bytes data) {
  co_return co_await offload(_blocking, [path = std::move(path), data = std::move(data)] { return append_now(path, data); });
}

Task<Status> SystemFiles::truncate(std::string path, std::uint64_t size) {
  co_return co_await offload(_blocking, [path = std::move(path), size] { return truncate_now(path, size); });
}

Task<Status> SystemFiles::remove(std::string path) {
  co_return co_await offload(_blocking, [path = std::move(path)] { return remove_now(path); });
}

Task<Status> SystemFiles::make_directory(std::string path) {
  co_return co_await offload(_blocking, [path = std::move(path)] { return make_directory_now(path); });
}

}  // namespace lugh::system
