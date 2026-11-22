//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A table's log as it is read at open: the header parse, the frame scan, and the
// torn-or-damaged decision, over whatever is on the disk. The key is fixed, so most frames
// fail to open; the header and framing are what is under test.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/fuzz/target.h"
#include "lugh/store/log_format.h"

namespace {

const lugh::SecureBuffer& fixed_key() {
  static const lugh::SecureBuffer key(32, 0x42);
  return key;
}

int run(const std::uint8_t* data, std::size_t size) {
  const auto key_for = [](std::uint32_t epoch) -> const lugh::SecureBuffer* { return epoch == 1 ? &fixed_key() : nullptr; };

  const std::span<const unsigned char> file(data, size);
  (void)lugh::store::decode_file_header(file);
  const auto scan = lugh::store::scan_log(file, "users", key_for);
  if (scan.ok && scan.value.valid_length > size) lugh::fuzz::finding("a log scan valid past the end of its file");
  return 0;
}

// Made by the writer under the fixed key, so the scan reaches past the seal: a header alone, and a
// header with a put and a remove after it.
std::vector<lugh::fuzz::Bytes> seeds() {
  using namespace lugh::store;
  const auto header = make_file_header("users", 1, fixed_key());
  if (!header.ok) throw std::runtime_error("no file header for the seeds: " + header.error);
  auto file = encode_file_header(header.value);
  std::vector<lugh::fuzz::Bytes> out{lugh::fuzz::Bytes(file.begin(), file.end())};

  auto previous = header.value.tag();
  for (const auto operation : {Operation::put, Operation::remove}) {
    Change change;
    change.operation = operation;
    change.version = operation == Operation::put ? 1 : 2;
    change.key = "u1";
    if (operation == Operation::put) change.value = lugh::SecureBuffer(8, 0x66);
    const auto framed = seal_change(change, "users", 1, fixed_key(), previous);
    if (!framed.ok) throw std::runtime_error("no frame for the seeds: " + framed.error);
    file.insert(file.end(), framed.value.bytes.begin(), framed.value.bytes.end());
    previous = framed.value.frame.tag();
  }
  out.emplace_back(file.begin(), file.end());
  return out;
}

const dannan::fuzz::Registration registered("store_log", [](std::span<const std::uint8_t> input) { run(input.data(), input.size()); }, seeds);

}  // namespace
