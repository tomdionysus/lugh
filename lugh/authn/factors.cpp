//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/factors.h"

#include <openssl/crypto.h>

#include "dannan/identity/crypto.h"
#include "lugh/authn/totp.h"
#include "lugh/core/codec.h"
#include "lugh/core/encoding.h"
#include "lugh/loggers/logger_scoped.h"

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::uint8_t kConfirmed = 0x01;
constexpr std::uint8_t kHasLastStep = 0x02;

constexpr std::size_t kLeastSecretBytes = 16;
constexpr std::size_t kMostSecretBytes = 64;
constexpr std::size_t kRecoveryCodeBytes = 10;
constexpr std::size_t kRecoveryCodeCharacters = 16;
constexpr std::size_t kSelectorCharacters = 4;
constexpr std::size_t kMostSlots = 16;

std::string_view kind_name(FactorKind kind) { return kind == FactorKind::totp ? "totp" : "recovery"; }

std::optional<FactorKind> kind_of(std::span<const unsigned char> value) {
  if (value.size() < 2 || value[0] != kFormat) return std::nullopt;
  if (value[1] == static_cast<std::uint8_t>(FactorKind::totp)) return FactorKind::totp;
  if (value[1] == static_cast<std::uint8_t>(FactorKind::recovery)) return FactorKind::recovery;
  return std::nullopt;
}

// "abcd-efgh-ijkl-mnop", for a person to copy down.
Secret display_code(std::string_view normal) {
  std::string out;
  out.reserve(kRecoveryCodeCharacters + 3);
  for (std::size_t i = 0; i < normal.size(); ++i) {
    if (i != 0 && i % 4 == 0) out.push_back('-');
    const char c = normal[i];
    out.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
  }
  return text_secret(std::move(out));
}

}  // namespace

SecureBuffer encode(const TotpRecord& record) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.u8(static_cast<std::uint8_t>(FactorKind::totp));
  writer.u8(static_cast<std::uint8_t>((record.confirmed ? kConfirmed : 0) | (record.last_step ? kHasLastStep : 0)));
  writer.u64(record.last_step.value_or(0));
  writer.u64(record.created);
  writer.bytes(record.secret);
  return writer.take();
}

std::optional<TotpRecord> decode_totp(std::span<const unsigned char> value) {
  if (kind_of(value) != FactorKind::totp) return std::nullopt;
  return decode_whole<TotpRecord>(value, [](dannan::net::Reader& reader) -> std::optional<TotpRecord> {
    reader.view(2);
    const auto flags = reader.u8();
    const auto last = reader.u64();
    const auto created = reader.u64();
    // The secret is read in place and copied straight into secure memory.
    const auto secret = reader.view_bytes(kMostSecretBytes);
    if ((flags & ~(kConfirmed | kHasLastStep)) != 0) return std::nullopt;
    // One encoding per record: no step is written as zero.
    if (!(flags & kHasLastStep) && last != 0) return std::nullopt;
    if (secret.size() < kLeastSecretBytes) return std::nullopt;

    TotpRecord record;
    record.confirmed = (flags & kConfirmed) != 0;
    if (flags & kHasLastStep) record.last_step = last;
    record.created = created;
    record.secret.assign(secret.begin(), secret.end());
    return record;
  });
}

SecureBuffer encode(const RecoveryRecord& record) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.u8(static_cast<std::uint8_t>(FactorKind::recovery));
  writer.u64(record.created);
  writer.u8(static_cast<std::uint8_t>(record.slots.size()));
  for (const auto& slot : record.slots) {
    writer.string(slot.selector);
    writer.u8(slot.used ? 1 : 0);
    write_password_hash(writer, slot.hash);
  }
  return writer.take();
}

std::optional<RecoveryRecord> decode_recovery(std::span<const unsigned char> value) {
  if (kind_of(value) != FactorKind::recovery) return std::nullopt;
  return decode_whole<RecoveryRecord>(value, [](dannan::net::Reader& reader) -> std::optional<RecoveryRecord> {
    reader.view(2);
    RecoveryRecord record;
    record.created = reader.u64();
    const auto count = reader.u8();
    if (count > kMostSlots) return std::nullopt;
    for (unsigned i = 0; i < count; ++i) {
      auto selector = reader.string(kSelectorCharacters);
      const auto used = reader.u8();
      if (selector.size() != kSelectorCharacters || used > 1) return std::nullopt;
      auto hash = read_password_hash(reader);
      if (!hash) return std::nullopt;
      record.slots.push_back(RecoverySlot{std::move(selector), used == 1, std::move(*hash)});
    }
    return record;
  });
}

std::optional<Secret> normal_recovery_code(std::string_view code) {
  if (code.size() > 2 * kRecoveryCodeCharacters) return std::nullopt;
  SecureBuffer out;
  for (const char c : code) {
    if (c == '-' || c == ' ') continue;
    const char upper = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
    if (!((upper >= 'A' && upper <= 'Z') || (upper >= '2' && upper <= '7'))) return std::nullopt;
    out.push_back(static_cast<unsigned char>(upper));
  }
  if (out.size() != kRecoveryCodeCharacters) return std::nullopt;
  return Secret(std::move(out));
}

Factors::Factors(std::shared_ptr<loggers::Logger> logger, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
                 std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs recovery_params)
    : _logger(std::make_shared<loggers::LoggerScoped>("factors", std::move(logger))),
      _store(std::move(store)),
      _wall(wall),
      _audit_log(std::move(audit)),
      _hashing(std::move(hashing)),
      _recovery_params(recovery_params) {}

Task<std::vector<FactorInfo>> Factors::list(std::string user_id) const {
  std::vector<FactorInfo> out;
  for (const auto& stored : co_await _records(std::move(user_id), std::nullopt)) {
    FactorInfo info;
    info.id = stored.key;
    if (const auto totp = decode_totp(stored.value)) {
      info.kind = FactorKind::totp;
      info.confirmed = totp->confirmed;
      info.created = totp->created;
    } else if (const auto recovery = decode_recovery(stored.value)) {
      info.kind = FactorKind::recovery;
      info.confirmed = true;
      info.created = recovery->created;
      for (const auto& slot : recovery->slots) info.remaining += slot.used ? 0 : 1;
    } else {
      continue;
    }
    out.push_back(std::move(info));
  }
  co_return out;
}

Task<bool> Factors::has_second_factor(std::string user_id) const {
  for (const auto& stored : co_await _records(std::move(user_id), FactorKind::totp)) {
    const auto totp = decode_totp(stored.value);
    if (totp && totp->confirmed) co_return true;
  }
  co_return false;
}

Task<Outcome<TotpSetup>> Factors::totp_begin(audit::Actor actor, std::string user_id, std::string issuer, std::string account) {
  using Answer = Outcome<TotpSetup>;
  for (const auto& stored : co_await _records(user_id, FactorKind::totp)) {
    const auto totp = decode_totp(stored.value);
    if (totp && !totp->confirmed) co_await _store->remove(kTable, stored.key, stored.version);
  }

  const auto key = _new_key(user_id, FactorKind::totp);
  if (!key) co_return Answer::failure(Fault::failed, "no randomness for an ID");

  TotpRecord record;
  record.created = (_wall.unix_ms() / 1000);
  record.secret = secure_random(kTotpSecretBytes);

  const auto written = co_await _store->put(kTable, *key, encode(record), 0);
  if (!written.ok()) co_return Answer::failure(directory::fault_of(written.error), written.message);
  co_await _audit(actor, "factor.totp.begin", user_id, *key);

  TotpSetup setup;
  setup.factor_id = *key;
  setup.secret = text_secret(encoding::base32(record.secret));
  setup.uri = otpauth_uri(issuer, account, record.secret);
  co_return Answer::success(std::move(setup));
}

Task<Outcome<>> Factors::totp_confirm(audit::Actor actor, std::string user_id, std::string factor_id, std::string code) {
  using Answer = Outcome<>;
  const auto prefix = user_id + "/totp/";
  if (factor_id.compare(0, prefix.size(), prefix) != 0) co_return Answer::failure(Fault::not_found, "no such factor");
  const auto stored = co_await _store->get(kTable, factor_id);
  auto record = stored ? decode_totp(stored->value) : std::nullopt;
  if (!record) co_return Answer::failure(Fault::not_found, "no such factor");
  if (record->confirmed) co_return Answer::failure(Fault::refused, "the factor is already confirmed");

  const auto step = totp_match(record->secret, code, (_wall.unix_ms() / 1000), std::nullopt);
  if (!step) {
    co_await _audit(actor, "factor.totp.confirm.refused", user_id, factor_id);
    co_return Answer::failure(Fault::refused, "the code is not right");
  }

  record->confirmed = true;
  record->last_step = *step;
  const auto written = co_await _store->put(kTable, factor_id, encode(*record), stored->version);
  if (!written.ok()) co_return Answer::failure(directory::fault_of(written.error), written.message);
  co_await _audit(actor, "factor.totp.confirm", user_id, factor_id);
  co_return Answer::success();
}

Task<Outcome<>> Factors::totp_check(std::string user_id, std::string code) {
  using Answer = Outcome<>;
  const auto now = (_wall.unix_ms() / 1000);
  for (const auto& stored : co_await _records(std::move(user_id), FactorKind::totp)) {
    auto record = decode_totp(stored.value);
    if (!record || !record->confirmed) continue;
    const auto step = totp_match(record->secret, code, now, record->last_step);
    if (!step) continue;

    record->last_step = *step;
    const auto written = co_await _store->put(kTable, stored.key, encode(*record), stored.version);
    if (written.ok()) co_return Answer::success();
    // Another sign-in used a code from this factor between the read and the write.
    if (written.error == store::StoreError::conflict) co_return Answer::failure(Fault::refused, "the code is not right");
    co_return Answer::failure(directory::fault_of(written.error), written.message);
  }
  co_return Answer::failure(Fault::refused, "the code is not right");
}

Task<Outcome<std::vector<Secret>>> Factors::recovery_generate(audit::Actor actor, std::string user_id) {
  using Answer = Outcome<std::vector<Secret>>;
  const auto old = co_await _records(user_id, FactorKind::recovery);

  // The codes are made here and hashed on the pool, ten at once, in one trip.
  struct Made {
    bool ok = false;
    std::string error;
    RecoveryRecord record;
    std::vector<Secret> codes;
  };
  auto made = co_await offload(_hashing, [params = _recovery_params, created = (_wall.unix_ms() / 1000)] {
    Made out;
    out.record.created = created;
    while (out.codes.size() < kRecoveryCodes) {
      const auto raw = secure_random(kRecoveryCodeBytes);
      auto normal = encoding::base32(raw);
      const auto selector = normal.substr(0, kSelectorCharacters);

      bool taken = false;
      for (const auto& slot : out.record.slots) taken = taken || slot.selector == selector;
      if (!taken) {
        auto hashed = hash_password(byte_span(normal), params);
        if (!hashed.ok) {
          OPENSSL_cleanse(normal.data(), normal.size());
          out.error = hashed.error;
          return out;
        }
        out.record.slots.push_back(RecoverySlot{selector, false, std::move(hashed.value)});
        out.codes.push_back(display_code(normal));
      }
      OPENSSL_cleanse(normal.data(), normal.size());
    }
    out.ok = true;
    return out;
  });
  if (!made.ok) co_return Answer::failure(Fault::failed, made.error);

  const auto key = _new_key(user_id, FactorKind::recovery);
  if (!key) co_return Answer::failure(Fault::failed, "no randomness for an ID");
  const auto written = co_await _store->put(kTable, *key, encode(made.record), 0);
  if (!written.ok()) co_return Answer::failure(directory::fault_of(written.error), written.message);

  // Only once the new set is in: a failure above leaves the old codes working.
  for (const auto& stored : old) co_await _store->remove(kTable, stored.key, stored.version);
  co_await _audit(actor, "factor.recovery.generate", user_id, *key);
  co_return Answer::success(std::move(made.codes));
}

Task<Outcome<std::size_t>> Factors::recovery_use(std::string user_id, Secret code) {
  using Answer = Outcome<std::size_t>;
  auto normal = normal_recovery_code(secret_text(code));

  for (const auto& stored : co_await _records(std::move(user_id), FactorKind::recovery)) {
    auto record = decode_recovery(stored.value);
    if (!record) continue;

    // Every slot's selector compared, whichever matches.
    std::optional<std::size_t> slot;
    const auto selector = normal ? normal->reveal().first(kSelectorCharacters) : std::span<const unsigned char>{};
    for (std::size_t i = 0; i < record->slots.size(); ++i) {
      const bool same = normal && dannan::identity::constant_time_equal(selector, byte_span(record->slots[i].selector));
      if (same && !record->slots[i].used) slot = i;
    }
    if (!slot) co_return Answer::failure(Fault::refused, "the code is not right");

    const bool right =
        co_await offload(_hashing, [code = std::move(*normal), hash = record->slots[*slot].hash] { return verify_password(code.reveal(), hash); });
    if (!right) co_return Answer::failure(Fault::refused, "the code is not right");

    record->slots[*slot].used = true;
    const auto written = co_await _store->put(kTable, stored.key, encode(*record), stored.version);
    if (!written.ok()) {
      if (written.error == store::StoreError::conflict) co_return Answer::failure(Fault::refused, "the code is not right");
      co_return Answer::failure(directory::fault_of(written.error), written.message);
    }

    std::size_t remaining = 0;
    for (const auto& one : record->slots) remaining += one.used ? 0 : 1;
    co_return Answer::success(remaining);
  }
  co_return Answer::failure(Fault::refused, "the code is not right");
}

Task<Outcome<>> Factors::remove(audit::Actor actor, std::string user_id, std::string factor_id) {
  using Answer = Outcome<>;
  const auto prefix = user_id + "/";
  if (factor_id.compare(0, prefix.size(), prefix) != 0 || !co_await _store->get(kTable, factor_id))
    co_return Answer::failure(Fault::not_found, "no such factor");
  const auto removed = co_await _store->remove(kTable, factor_id);
  if (!removed.ok()) co_return Answer::failure(directory::fault_of(removed.error), removed.message);
  co_await _audit(actor, "factor.remove", user_id, factor_id);
  co_return Answer::success();
}

Task<Status> Factors::forget(audit::Actor actor, std::string user_id) {
  const auto all = co_await _records(user_id, std::nullopt);
  if (all.empty()) co_return Status::success();
  std::string failed;
  for (const auto& stored : all) {
    const auto removed = co_await _store->remove(kTable, stored.key);
    if (!removed.ok() && removed.error != store::StoreError::removed) failed = removed.message;
  }
  co_await _audit(actor, "factor.reset", user_id, std::to_string(all.size()) + " removed");
  co_return failed.empty() ? Status::success() : Status::failure("cannot remove every factor: " + failed);
}

Task<std::vector<Factors::Stored>> Factors::_records(std::string user_id, std::optional<FactorKind> kind) const {
  const auto prefix = user_id + "/" + (kind ? std::string(kind_name(*kind)) + "/" : "");
  std::vector<Stored> out;
  for (auto& record : co_await _store->list(kTable)) {
    if (record.key.compare(0, prefix.size(), prefix) != 0) continue;
    out.push_back(Stored{std::move(record.key), record.version, std::move(record.value)});
  }
  co_return out;
}

std::optional<std::string> Factors::_new_key(std::string_view user_id, FactorKind kind) {
  const auto instance = dannan::identity::random_bytes(8);
  if (instance.empty()) return std::nullopt;
  return std::string(user_id) + "/" + std::string(kind_name(kind)) + "/" + dannan::identity::hex(instance);
}

Task<void> Factors::_audit(const audit::Actor& actor, std::string action, std::string user_id, std::string detail) {
  co_await _audit_log->record(audit::Event{std::move(action), actor.id, std::move(user_id), actor.source, std::move(detail)});
}

}  // namespace lugh::authn
