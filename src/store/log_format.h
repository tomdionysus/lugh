#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/secure_bytes.h"
#include "core/status.h"
#include "system/random.h"

namespace lugh::store {

// A table's log, after Macha's sealed journal: append-only, every frame sealed, fsynced
// before a write is acknowledged, and a torn tail cut off at the next open.
//
// The file is
//
//   "LUGHTBL1"  8
//   table       1 length, then the name
//   id          16, random, new with every rewrite
//   epoch       4   the data key epoch the header is sealed under
//   seal        nonce 12 | tag 16: nothing, sealed with the bytes above as associated data
//   frames
//
// The header's seal proves the keyring opens this table before any frame is judged, so a
// wrong keyring is refused outright and never mistaken for a torn tail. The header is
// written whole, with the file, so it is never torn itself.
//
// and a frame is
//
//   "LREC"      4
//   epoch       4   the table's data key epoch it is sealed under
//   length      4   of the sealed part
//   check       8   the first bytes of SHA-256 over the 12 above
//   sealed      nonce 12 | ciphertext | tag 16
//
// sealed with AES-256-GCM under the epoch's data key. The associated data is
// "lugh record v1", the table, the epoch, and the previous frame's tag (the header seal's
// for the first), so a frame cannot be moved to another table or file, reordered, dropped
// from the middle or replayed later. The check lets a scan tell a torn tail (no frame
// header anywhere after the break) from damage in the middle (a frame header after it),
// as Macha's pack recovery does; it is a crash detector, not a defence, which the seal is.
//
// The plaintext is
//
//   operation   1   (1 put, 2 remove)
//   version     8
//   key         2 length, then the key
//   value       the rest; empty for a remove

inline constexpr std::size_t kFileIdBytes = 16;
inline constexpr std::size_t kTagBytes = 16;
inline constexpr std::size_t kFrameHeaderBytes = 20;
inline constexpr std::size_t kMostKeyBytes = 255;
inline constexpr std::size_t kMostValueBytes = 256 * 1024;
inline constexpr std::size_t kMostTableNameBytes = 64;
inline constexpr std::size_t kMostTableFileBytes = 256 * 1024 * 1024;

enum class Operation : std::uint8_t { put = 1, remove = 2 };

// What a frame says, once opened.
struct Change {
  Operation operation = Operation::put;
  std::uint64_t version = 0;
  std::string key;
  SecureBytes value;
};

struct FileHeader {
  std::string table;
  Bytes id;
  std::uint32_t epoch = 0;
  // nonce | tag.
  Bytes seal;

  // What the first frame names as the one before it.
  Bytes tag() const { return Bytes(seal.end() - static_cast<std::ptrdiff_t>(kTagBytes), seal.end()); }
};

// A new header for a table, with a fresh id, sealed under the epoch's key.
Result<FileHeader> make_file_header(std::string_view table, std::uint32_t epoch, std::span<const unsigned char> key, system::Random& random);

Bytes encode_file_header(const FileHeader& header);

struct ParsedFileHeader {
  FileHeader header;
  std::size_t length = 0;
};

// The fields, not yet proven: verify_file_header() does that.
std::optional<ParsedFileHeader> decode_file_header(std::span<const unsigned char> file);

bool verify_file_header(const FileHeader& header, std::span<const unsigned char> key);

// A frame as it sits on disk, for the store to keep and open again on a read.
struct SealedFrame {
  std::uint32_t epoch = 0;
  // The tag this frame's associated data names: the frame before's, or the file id.
  Bytes previous;
  // nonce | ciphertext | tag.
  Bytes sealed;

  // This frame's own tag, which the next frame names.
  Bytes tag() const { return Bytes(sealed.end() - static_cast<std::ptrdiff_t>(kTagBytes), sealed.end()); }

  // Its length on disk.
  std::size_t size() const { return kFrameHeaderBytes + sealed.size(); }
};

// Seals a change into a frame, and the bytes to append.
struct Framed {
  SealedFrame frame;
  Bytes bytes;
};

Result<Framed> seal_change(const Change& change, std::string_view table, std::uint32_t epoch, std::span<const unsigned char> key,
                           std::span<const unsigned char> previous, system::Random& random);

// Opens a frame the store kept.
std::optional<Change> open_frame(const SealedFrame& frame, std::string_view table, std::span<const unsigned char> key);

// The data key for an epoch, or null when the keyring has none.
using KeyFor = std::function<const SecureBytes*(std::uint32_t epoch)>;

struct Scan {
  FileHeader header;

  struct Entry {
    SealedFrame frame;
    Change change;
  };
  std::vector<Entry> entries;

  // Where the last frame that opened ends: the length the file is cut to after a torn tail.
  std::size_t valid_length = 0;

  enum class End { clean, torn, damaged };
  End end = End::clean;

  // For a torn or damaged end: where, and why.
  std::size_t problem_offset = 0;
  std::string problem;
};

// Reads a table's log. A header that is not one, names another table, or does not open
// under the keyring's key for its epoch, is a failure. Frames are read until one does not
// open; what follows decides whether that was a torn tail or damage, and the scan says
// which. Fuzzed (fuzz/store_log_fuzz.cpp).
Result<Scan> scan_log(std::span<const unsigned char> file, std::string_view table, const KeyFor& key_for);

}  // namespace lugh::store
