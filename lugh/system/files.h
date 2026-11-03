//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <string>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"
#include "lugh/core/task.h"

namespace lugh::system {

// The files Lugh keeps of its own, from outside, so the key hierarchy and the store can be
// tested without a disk. Not for the configuration or the TLS pair, which are read once at
// start by the code that understands them.
//
// Every call is awaited: the caller suspends while the disk works. Arguments are owned, not
// borrowed, because the caller's buffers need not outlive a suspension.
class Files {
 public:
  virtual ~Files() = default;

  virtual Task<bool> exists(std::string path) const = 0;

  // The whole of a regular file. A symlink, a directory, or anything larger than `most`
  // is refused, with the reason.
  virtual Task<Result<Bytes>> read(std::string path, std::size_t most) const = 0;

  // The same, into locked memory, for a file that holds a key.
  virtual Task<Result<SecureBuffer>> read_secret(std::string path, std::size_t most) const = 0;

  // Writes the whole file, mode 0600, so that a crash leaves either the old file or the new
  // one, never part of either: a temporary beside it, synced, then moved into place, then
  // the directory synced. With `replace` false, an existing file is an error and is left
  // as it was.
  virtual Task<Status> write(std::string path, Bytes data, bool replace) = 0;

  // Adds to the end of an existing file and syncs it before answering, so what was appended
  // survives a crash once this says ok. A failure may leave part of it appended: the caller
  // truncates back to where it was.
  virtual Task<Status> append(std::string path, Bytes data) = 0;

  // Cuts an existing file to `size` bytes, synced.
  virtual Task<Status> truncate(std::string path, std::uint64_t size) = 0;

  // Removes a file, if there is one, and syncs its directory.
  virtual Task<Status> remove(std::string path) = 0;

  // A directory, mode 0700, and any missing above it. One that exists is fine.
  virtual Task<Status> make_directory(std::string path) = 0;
};

}  // namespace lugh::system
