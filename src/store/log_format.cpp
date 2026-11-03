//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "store/log_format.h"

#include <algorithm>
#include <utility>

#include "core/byte_io.h"
#include "crypto/aead.h"
#include "crypto/digest.h"

namespace lugh::store {

namespace {

constexpr std::string_view kFileMagic = "LUGHTBL1";
constexpr std::string_view kFrameMagic = "LREC";
constexpr std::string_view kRecordContext = "lugh record v1";
constexpr std::string_view kTableContext = "lugh table v1";
constexpr std::size_t kHeaderSealBytes = crypto::kAeadOverhead;

// What the header's seal covers: everything in the header before it.
Bytes header_fields(const FileHeader& header) {
  Bytes out;
  ByteWriter writer(out);
  writer.text("LUGHTBL1");
  writer.u8(static_cast<std::uint8_t>(header.table.size()));
  writer.text(header.table);
  writer.bytes(header.id);
  writer.u32(header.epoch);
  return out;
}

Bytes header_associated(const FileHeader& header) {
  Bytes out;
  ByteWriter writer(out);
  writer.text(kTableContext);
  writer.u8(0);
  writer.bytes(header_fields(header));
  return out;
}
constexpr std::size_t kCheckBytes = 8;

// The most a sealed part can be: the largest change, sealed.
constexpr std::size_t kMostSealedBytes = 1 + 8 + 2 + kMostKeyBytes + kMostValueBytes + crypto::kAeadOverhead;

Bytes associated_data(std::string_view table, std::uint32_t epoch, std::span<const unsigned char> previous) {
  Bytes out;
  ByteWriter writer(out);
  writer.text(kRecordContext);
  writer.u8(0);
  writer.u8(static_cast<std::uint8_t>(table.size()));
  writer.text(table);
  writer.u32(epoch);
  writer.bytes(previous);
  return out;
}

std::array<unsigned char, kCheckBytes> check_of(std::span<const unsigned char> header_prefix) {
  const auto digest = crypto::sha256(header_prefix);
  std::array<unsigned char, kCheckBytes> out{};
  std::copy_n(digest.begin(), kCheckBytes, out.begin());
  return out;
}

struct FrameHeader {
  std::uint32_t epoch = 0;
  std::uint32_t length = 0;
};

// A frame header at the start of `bytes`, if there is a whole one whose check holds.
std::optional<FrameHeader> frame_header_at(std::span<const unsigned char> bytes) {
  if (bytes.size() < kFrameHeaderBytes) return std::nullopt;
  if (!std::equal(kFrameMagic.begin(), kFrameMagic.end(), bytes.begin())) return std::nullopt;

  const auto check = check_of(bytes.first(12));
  if (!std::equal(check.begin(), check.end(), bytes.begin() + 12)) return std::nullopt;

  ByteReader reader(bytes.subspan(4, 8));
  FrameHeader header;
  header.epoch = *reader.u32();
  header.length = *reader.u32();
  if (header.epoch == 0 || header.length < crypto::kAeadOverhead || header.length > kMostSealedBytes) return std::nullopt;
  return header;
}

// Whether a frame header starts anywhere at or after `from`.
bool header_after(std::span<const unsigned char> file, std::size_t from) {
  for (std::size_t at = from; at + kFrameHeaderBytes <= file.size(); ++at) {
    const auto found = std::search(file.begin() + static_cast<std::ptrdiff_t>(at), file.end(), kFrameMagic.begin(), kFrameMagic.end());
    if (found == file.end()) return false;
    at = static_cast<std::size_t>(found - file.begin());
    if (frame_header_at(file.subspan(at))) return true;
  }
  return false;
}

std::optional<Change> decode_change(std::span<const unsigned char> plaintext) {
  ByteReader reader(plaintext);

  Change change;
  const auto operation = reader.u8();
  if (operation == static_cast<std::uint8_t>(Operation::put)) {
    change.operation = Operation::put;
  } else if (operation == static_cast<std::uint8_t>(Operation::remove)) {
    change.operation = Operation::remove;
  } else {
    return std::nullopt;
  }

  const auto version = reader.u64();
  const auto key_length = reader.u16();
  if (!version || *version == 0 || !key_length || *key_length == 0 || *key_length > kMostKeyBytes) return std::nullopt;
  const auto key = reader.bytes(*key_length);
  if (!key) return std::nullopt;

  change.version = *version;
  change.key.assign(key->begin(), key->end());

  const auto value = reader.rest();
  if (change.operation == Operation::remove && !value.empty()) return std::nullopt;
  if (value.size() > kMostValueBytes) return std::nullopt;
  change.value.assign(value.begin(), value.end());
  return change;
}

}  // namespace

Result<FileHeader> make_file_header(std::string_view table, std::uint32_t epoch, std::span<const unsigned char> key, system::Random& random) {
  using Answer = Result<FileHeader>;
  if (table.empty() || table.size() > kMostTableNameBytes || epoch == 0) return Answer::failure("a header needs a table and an epoch");

  FileHeader header;
  header.table = std::string(table);
  header.epoch = epoch;
  header.id = random.bytes(kFileIdBytes);
  if (header.id.size() != kFileIdBytes) return Answer::failure("no randomness for a file id");

  auto seal = crypto::seal(key, {}, header_associated(header), random);
  if (!seal.ok) return Answer::failure(seal.error);
  header.seal = std::move(seal.value);
  return Answer::success(std::move(header));
}

Bytes encode_file_header(const FileHeader& header) {
  auto out = header_fields(header);
  out.insert(out.end(), header.seal.begin(), header.seal.end());
  return out;
}

bool verify_file_header(const FileHeader& header, std::span<const unsigned char> key) {
  const auto opened = crypto::open(key, header.seal, header_associated(header));
  return opened && opened->empty();
}

std::optional<ParsedFileHeader> decode_file_header(std::span<const unsigned char> file) {
  ByteReader reader(file);
  const auto magic = reader.bytes(kFileMagic.size());
  if (!magic || !std::equal(magic->begin(), magic->end(), kFileMagic.begin())) return std::nullopt;

  const auto name_length = reader.u8();
  if (!name_length || *name_length == 0 || *name_length > kMostTableNameBytes) return std::nullopt;
  const auto name = reader.bytes(*name_length);
  const auto id = reader.bytes(kFileIdBytes);
  const auto epoch = reader.u32();
  const auto seal = reader.bytes(kHeaderSealBytes);
  if (!name || !id || !epoch || *epoch == 0 || !seal) return std::nullopt;

  ParsedFileHeader parsed;
  parsed.header.table.assign(name->begin(), name->end());
  parsed.header.id.assign(id->begin(), id->end());
  parsed.header.epoch = *epoch;
  parsed.header.seal.assign(seal->begin(), seal->end());
  parsed.length = reader.offset();
  return parsed;
}

Result<Framed> seal_change(const Change& change, std::string_view table, std::uint32_t epoch, std::span<const unsigned char> key,
                           std::span<const unsigned char> previous, system::Random& random) {
  using Answer = Result<Framed>;
  if (change.key.empty() || change.key.size() > kMostKeyBytes) return Answer::failure("a key is 1 to 255 bytes");
  if (change.value.size() > kMostValueBytes) return Answer::failure("a value is at most 256 KiB");
  if (change.operation == Operation::remove && !change.value.empty()) return Answer::failure("a remove carries no value");
  if (change.version == 0 || epoch == 0 || previous.size() != kTagBytes) return Answer::failure("a frame needs a version, an epoch and a chain");

  SecureBytes plaintext;
  ByteWriter body(plaintext);
  body.u8(static_cast<std::uint8_t>(change.operation));
  body.u64(change.version);
  body.u16(static_cast<std::uint16_t>(change.key.size()));
  body.text(change.key);
  body.bytes(change.value);

  auto sealed = crypto::seal(key, plaintext, associated_data(table, epoch, previous), random);
  if (!sealed.ok) return Answer::failure(sealed.error);

  Framed out;
  out.frame.epoch = epoch;
  out.frame.previous.assign(previous.begin(), previous.end());
  out.frame.sealed = std::move(sealed.value);

  ByteWriter writer(out.bytes);
  writer.text(kFrameMagic);
  writer.u32(epoch);
  writer.u32(static_cast<std::uint32_t>(out.frame.sealed.size()));
  const auto check = check_of(out.bytes);
  writer.bytes(check);
  writer.bytes(out.frame.sealed);
  return Answer::success(std::move(out));
}

std::optional<Change> open_frame(const SealedFrame& frame, std::string_view table, std::span<const unsigned char> key) {
  const auto plaintext = crypto::open(key, frame.sealed, associated_data(table, frame.epoch, frame.previous));
  if (!plaintext) return std::nullopt;
  return decode_change(*plaintext);
}

Result<Scan> scan_log(std::span<const unsigned char> file, std::string_view table, const KeyFor& key_for) {
  using Answer = Result<Scan>;

  const auto parsed = decode_file_header(file);
  if (!parsed) return Answer::failure("not a Lugh table log");
  if (parsed->header.table != table) return Answer::failure("the log is table " + parsed->header.table + "'s, not " + std::string(table) + "'s");

  const auto* header_key = key_for(parsed->header.epoch);
  if (header_key == nullptr) return Answer::failure("the keyring has no data key for the log's epoch " + std::to_string(parsed->header.epoch));
  if (!verify_file_header(parsed->header, *header_key)) {
    return Answer::failure("the keyring's data key does not open the log's header: this is another keyring's table, or the header was altered");
  }

  Scan scan;
  scan.header = parsed->header;
  scan.valid_length = parsed->length;

  Bytes previous = parsed->header.tag();
  std::size_t offset = parsed->length;

  const auto stop = [&](std::string why) {
    scan.problem_offset = offset;
    scan.problem = std::move(why);
    scan.end = header_after(file, offset + 1) ? Scan::End::damaged : Scan::End::torn;
  };

  while (offset < file.size()) {
    const auto header = frame_header_at(file.subspan(offset));
    if (!header) {
      stop("no frame header");
      break;
    }
    if (header->length > file.size() - offset - kFrameHeaderBytes) {
      stop("a frame runs past the end");
      break;
    }

    const auto* key = key_for(header->epoch);
    if (key == nullptr) {
      // A frame under an epoch this node has no key for is not a torn write.
      scan.problem_offset = offset;
      scan.problem = "no data key for epoch " + std::to_string(header->epoch);
      scan.end = Scan::End::damaged;
      break;
    }

    Scan::Entry entry;
    entry.frame.epoch = header->epoch;
    entry.frame.previous = previous;
    const auto sealed = file.subspan(offset + kFrameHeaderBytes, header->length);
    entry.frame.sealed.assign(sealed.begin(), sealed.end());

    auto change = open_frame(entry.frame, table, *key);
    if (!change) {
      stop("a frame does not open");
      break;
    }
    entry.change = std::move(*change);

    previous = entry.frame.tag();
    offset += entry.frame.size();
    scan.valid_length = offset;
    scan.entries.push_back(std::move(entry));
  }

  return Answer::success(std::move(scan));
}

}  // namespace lugh::store
