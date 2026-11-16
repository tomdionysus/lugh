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
#include "lugh/core/steps.h"
#include "lugh/directory/records.h"

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

// A WebAuthn credential's limits: a name a person types; the ids and keys WebAuthn allows.
constexpr std::size_t kMostCredentialNameBytes = 64;
constexpr std::size_t kMostCredentialIdBytes = 1023;
constexpr std::size_t kMostKeyBytes = 1024;
constexpr std::size_t kMostExponentBytes = 16;
constexpr std::uint8_t kBackupEligible = 0x01;
constexpr std::uint8_t kBackedUp = 0x02;

std::string_view kind_name(FactorKind kind) {
  switch (kind) {
    case FactorKind::totp:
      return "totp";
    case FactorKind::recovery:
      return "recovery";
    case FactorKind::webauthn:
      return "webauthn";
  }
  return "unknown";
}

std::optional<FactorKind> kind_of(std::span<const unsigned char> value) {
  if (value.size() < 2 || value[0] != kFormat) return std::nullopt;
  if (value[1] == static_cast<std::uint8_t>(FactorKind::totp)) return FactorKind::totp;
  if (value[1] == static_cast<std::uint8_t>(FactorKind::recovery)) return FactorKind::recovery;
  if (value[1] == static_cast<std::uint8_t>(FactorKind::webauthn)) return FactorKind::webauthn;
  return std::nullopt;
}

FactorInfo info_of(const std::string& key, const WebAuthnRecord& record) {
  FactorInfo info;
  info.id = key;
  info.kind = FactorKind::webauthn;
  info.confirmed = true;
  info.created = record.created;
  info.name = record.name;
  info.aaguid = dannan::identity::hex(record.aaguid);
  info.backed_up = record.backed_up;
  info.last_used = record.last_used;
  return info;
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

SecureBuffer encode(const WebAuthnRecord& record) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.u8(static_cast<std::uint8_t>(FactorKind::webauthn));
  writer.u64(record.created);
  writer.u64(record.last_used);
  writer.string(record.name);
  writer.string(record.credential_id);
  writer.u8(static_cast<std::uint8_t>(record.key.kind));
  if (record.key.kind == webauthn::PublicKey::Kind::rs256) {
    writer.string(record.key.modulus);
    writer.string(record.key.exponent);
  } else {
    writer.bytes(record.key.der);
    writer.string({});
  }
  writer.u32(record.sign_count);
  writer.u8(static_cast<std::uint8_t>((record.backup_eligible ? kBackupEligible : 0) | (record.backed_up ? kBackedUp : 0)));
  writer.fixed(record.aaguid);
  return writer.take();
}

std::optional<WebAuthnRecord> decode_webauthn(std::span<const unsigned char> value) {
  if (kind_of(value) != FactorKind::webauthn) return std::nullopt;
  return decode_whole<WebAuthnRecord>(value, [](dannan::net::Reader& reader) -> std::optional<WebAuthnRecord> {
    reader.view(2);
    WebAuthnRecord record;
    record.created = reader.u64();
    record.last_used = reader.u64();
    record.name = reader.string(kMostCredentialNameBytes);
    record.credential_id = reader.string(kMostCredentialIdBytes);
    const auto kind = reader.u8();
    auto first = reader.string(kMostKeyBytes);
    auto second = reader.string(kMostExponentBytes);
    switch (kind) {
      case static_cast<std::uint8_t>(webauthn::PublicKey::Kind::es256):
      case static_cast<std::uint8_t>(webauthn::PublicKey::Kind::eddsa):
        if (first.empty() || !second.empty()) return std::nullopt;
        record.key.kind = static_cast<webauthn::PublicKey::Kind>(kind);
        record.key.der.assign(first.begin(), first.end());
        break;
      case static_cast<std::uint8_t>(webauthn::PublicKey::Kind::rs256):
        if (first.empty() || second.empty()) return std::nullopt;
        record.key.kind = webauthn::PublicKey::Kind::rs256;
        record.key.modulus = std::move(first);
        record.key.exponent = std::move(second);
        break;
      default:
        return std::nullopt;
    }
    record.sign_count = reader.u32();
    const auto flags = reader.u8();
    if ((flags & ~(kBackupEligible | kBackedUp)) != 0) return std::nullopt;
    record.backup_eligible = (flags & kBackupEligible) != 0;
    record.backed_up = (flags & kBackedUp) != 0;
    if (record.backed_up && !record.backup_eligible) return std::nullopt;
    record.aaguid = reader.fixed<16>();
    if (record.credential_id.empty()) return std::nullopt;
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

Factors::Factors(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
                 std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs recovery_params)
    : _logger(std::move(log), "factors"),
      _calls(std::move(store)),
      _wall(wall),
      _audit_log(std::move(audit)),
      _hashing(std::move(hashing)),
      _recovery_params(recovery_params) {}

namespace {

constexpr const char* kChangeLate = "the factors did not answer within the deadline; the change may yet be made";
constexpr const char* kReadLate = "the factors were not read within the deadline";
constexpr const char* kWrongCode = "the code is not right";
constexpr Deadline kAuditDeadline = std::chrono::seconds(30);

}  // namespace

void Factors::list(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<FactorInfo>>> done) const {
  using Answer = Outcome<std::vector<FactorInfo>>;
  auto answer = answering<std::vector<FactorInfo>>(deadline, executor, std::move(done), kReadLate);
  _records(std::move(user_id), std::nullopt, executor, [answer](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    std::vector<FactorInfo> out;
    for (const auto& stored : records.value) {
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
      } else if (const auto credential = decode_webauthn(stored.value)) {
        info = info_of(stored.key, *credential);
      } else {
        continue;
      }
      out.push_back(std::move(info));
    }
    answer->finish(Answer::success(std::move(out)));
  });
}

void Factors::has_second_factor(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<bool>> done) const {
  using Answer = Outcome<bool>;
  auto answer = answering<bool>(deadline, executor, std::move(done), kReadLate);
  _records(std::move(user_id), std::nullopt, executor, [answer](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    for (const auto& stored : records.value) {
      const auto totp = decode_totp(stored.value);
      if (totp && totp->confirmed) return answer->finish(Answer::success(true));
      if (decode_webauthn(stored.value)) return answer->finish(Answer::success(true));
    }
    answer->finish(Answer::success(false));
  });
}

void Factors::totp_begin(audit::Actor actor, std::string user_id, std::string issuer, std::string account, Deadline deadline, Executor executor,
                         Done<Outcome<TotpSetup>> done) {
  using Answer = Outcome<TotpSetup>;
  auto answer = answering<TotpSetup>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _records(user_id, FactorKind::totp, executor, [=](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    auto unconfirmed = std::make_shared<std::vector<Stored>>();
    for (auto& stored : records.value) {
      const auto totp = decode_totp(stored.value);
      if (totp && !totp->confirmed) unconfirmed->push_back(std::move(stored));
    }
    in_turn<Stored>(
        unconfirmed, 0,
        [=](const Stored& stored, std::function<void()> next) {
          self->_calls.remove_settled(kTable, stored.key, stored.version, executor, [next](store::Write) { next(); });
        },
        [=] {
          const auto key = self->_new_key(user_id, FactorKind::totp);
          if (!key) return answer->finish(Answer::failure(Fault::failed, "no randomness for an ID"));
          auto record = std::make_shared<TotpRecord>();
          record->created = (self->_wall.unix_ms() / 1000);
          record->secret = secure_random(kTotpSecretBytes);
          self->_calls.put_settled(kTable, *key, encode(*record), 0, executor, [=](store::Write written) {
            if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
            self->_record(actor, "factor.totp.begin", user_id, *key, executor, [=] {
              TotpSetup setup;
              setup.factor_id = *key;
              setup.secret = text_secret(encoding::base32(record->secret));
              setup.uri = otpauth_uri(issuer, account, record->secret);
              answer->finish(Answer::success(std::move(setup)));
            });
          });
        });
  });
}

void Factors::totp_confirm(audit::Actor actor, std::string user_id, std::string factor_id, std::string code, Deadline deadline, Executor executor,
                           Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  const auto prefix = user_id + "/totp/";
  if (factor_id.compare(0, prefix.size(), prefix) != 0) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));
  auto self = shared_from_this();
  _calls.get_settled(kTable, factor_id, executor, [=](Outcome<std::optional<store::Record>> stored) {
    if (!stored.ok()) return answer->finish(Answer::from(stored));
    auto record = stored.value ? decode_totp(stored.value->value) : std::nullopt;
    if (!record) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));
    if (record->confirmed) return answer->finish(Answer::failure(Fault::refused, "the factor is already confirmed"));

    const auto step = totp_match(record->secret, code, (self->_wall.unix_ms() / 1000), std::nullopt);
    if (!step) {
      return self->_record(actor, "factor.totp.confirm.refused", user_id, factor_id, executor,
                           [answer] { answer->finish(Answer::failure(Fault::refused, kWrongCode)); });
    }
    record->confirmed = true;
    record->last_step = *step;
    self->_calls.put_settled(kTable, factor_id, encode(*record), stored.value->version, executor, [=](store::Write written) {
      if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
      self->_record(actor, "factor.totp.confirm", user_id, factor_id, executor, [answer] { answer->finish(Answer::success()); });
    });
  });
}

void Factors::totp_check(std::string user_id, std::string code, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kReadLate);
  auto self = shared_from_this();
  _records(std::move(user_id), FactorKind::totp, executor, [=](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    const auto now = (self->_wall.unix_ms() / 1000);
    // The first confirmed factor the code is right for, at a step not yet used.
    for (const auto& stored : records.value) {
      auto record = decode_totp(stored.value);
      if (!record || !record->confirmed) continue;
      const auto step = totp_match(record->secret, code, now, record->last_step);
      if (!step) continue;
      record->last_step = *step;
      return self->_calls.put_settled(kTable, stored.key, encode(*record), stored.version, executor, [answer](store::Write written) {
        if (written.ok()) return answer->finish(Answer::success());
        // Another sign-in used a code from this factor between the read and the write.
        if (written.error == store::StoreError::conflict) return answer->finish(Answer::failure(Fault::refused, kWrongCode));
        answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
      });
    }
    answer->finish(Answer::failure(Fault::refused, kWrongCode));
  });
}

void Factors::recovery_generate(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<Secret>>> done) {
  using Answer = Outcome<std::vector<Secret>>;
  auto answer = answering<std::vector<Secret>>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _records(user_id, FactorKind::recovery, executor, [=](Outcome<std::vector<Stored>> old) {
    if (!old.ok()) return answer->finish(Answer::from(old));
    auto earlier = std::make_shared<std::vector<Stored>>(std::move(old.value));

    // The codes are made here and hashed on the pool, ten at once, in one trip.
    struct Made {
      bool ok = false;
      std::string error;
      RecoveryRecord record;
      std::vector<Secret> codes;
    };
    on_pool(
        self->_hashing,
        [params = self->_recovery_params, created = (self->_wall.unix_ms() / 1000)] {
          auto out = std::make_shared<Made>();
          out->record.created = created;
          while (out->codes.size() < kRecoveryCodes) {
            const auto raw = secure_random(kRecoveryCodeBytes);
            auto normal = encoding::base32(raw);
            const auto selector = normal.substr(0, kSelectorCharacters);

            bool taken = false;
            for (const auto& slot : out->record.slots) taken = taken || slot.selector == selector;
            if (!taken) {
              auto hashed = hash_password(byte_span(normal), params);
              if (!hashed.ok) {
                OPENSSL_cleanse(normal.data(), normal.size());
                out->error = hashed.error;
                return out;
              }
              out->record.slots.push_back(RecoverySlot{selector, false, std::move(hashed.value)});
              out->codes.push_back(display_code(normal));
            }
            OPENSSL_cleanse(normal.data(), normal.size());
          }
          out->ok = true;
          return out;
        },
        executor,
        [=](std::shared_ptr<Made> made) {
          if (!made->ok) return answer->finish(Answer::failure(Fault::failed, made->error));
          const auto key = self->_new_key(user_id, FactorKind::recovery);
          if (!key) return answer->finish(Answer::failure(Fault::failed, "no randomness for an ID"));
          self->_calls.put_settled(kTable, *key, encode(made->record), 0, executor, [=](store::Write written) {
            if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
            // Only once the new set is in: a failure above leaves the old codes working.
            in_turn<Stored>(
                earlier, 0,
                [=](const Stored& stored, std::function<void()> next) {
                  self->_calls.remove_settled(kTable, stored.key, stored.version, executor, [next](store::Write) { next(); });
                },
                [=] {
                  self->_record(actor, "factor.recovery.generate", user_id, *key, executor,
                                [answer, made] { answer->finish(Answer::success(std::move(made->codes))); });
                });
          });
        });
  });
}

void Factors::recovery_use(std::string user_id, Secret code, Deadline deadline, Executor executor, Done<Outcome<std::size_t>> done) {
  using Answer = Outcome<std::size_t>;
  auto answer = answering<std::size_t>(deadline, executor, std::move(done), kReadLate);
  auto normal = normal_recovery_code(secret_text(code));
  auto held = std::make_shared<std::optional<Secret>>(std::move(normal));
  auto self = shared_from_this();
  _records(std::move(user_id), FactorKind::recovery, executor, [=](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    for (const auto& stored : records.value) {
      auto record = decode_recovery(stored.value);
      if (!record) continue;

      // Every slot's selector compared, whichever matches.
      std::optional<std::size_t> slot;
      const auto& typed = *held;
      const auto selector = typed ? typed->reveal().first(kSelectorCharacters) : std::span<const unsigned char>{};
      for (std::size_t i = 0; i < record->slots.size(); ++i) {
        const bool same = typed && dannan::identity::constant_time_equal(selector, byte_span(record->slots[i].selector));
        if (same && !record->slots[i].used) slot = i;
      }
      if (!slot) return answer->finish(Answer::failure(Fault::refused, kWrongCode));

      auto kept = std::make_shared<RecoveryRecord>(std::move(*record));
      const auto key = stored.key;
      const auto version = stored.version;
      const auto which = *slot;
      return on_pool(
          self->_hashing, [held, hash = kept->slots[which].hash] { return verify_password((*held)->reveal(), hash); }, executor,
          [=](bool right) {
            if (!right) return answer->finish(Answer::failure(Fault::refused, kWrongCode));
            kept->slots[which].used = true;
            self->_calls.put_settled(kTable, key, encode(*kept), version, executor, [answer, kept](store::Write written) {
              if (!written.ok()) {
                if (written.error == store::StoreError::conflict) return answer->finish(Answer::failure(Fault::refused, kWrongCode));
                return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
              }
              std::size_t remaining = 0;
              for (const auto& one : kept->slots) remaining += one.used ? 0 : 1;
              answer->finish(Answer::success(remaining));
            });
          });
    }
    answer->finish(Answer::failure(Fault::refused, kWrongCode));
  });
}

void Factors::webauthn_register(audit::Actor actor, std::string user_id, std::string name, webauthn::Expected expected, Bytes client_data_json,
                                Bytes attestation_object, Deadline deadline, Executor executor, Done<Outcome<FactorInfo>> done) {
  using Answer = Outcome<FactorInfo>;
  auto answer = answering<FactorInfo>(deadline, executor, std::move(done), kChangeLate);
  if (name.empty() || !directory::printable(name, kMostCredentialNameBytes))
    return answer->finish(Answer::failure(Fault::invalid, "a credential's name is 1 to 64 printable bytes"));
  const auto checked = webauthn::check_registration(expected, client_data_json, attestation_object);
  if (!checked.ok()) {
    return _record(actor, "factor.webauthn.register.refused", user_id, checked.message, executor, [answer, checked] { answer->finish(Answer::from(checked)); });
  }
  auto self = shared_from_this();
  // Every user's credentials, since an id registered to anyone is refused.
  _calls.list_settled(kTable, executor, [=](Outcome<std::vector<store::Record>> all) {
    if (!all.ok()) return answer->finish(Answer::from(all));
    for (const auto& stored : all.value) {
      const auto existing = decode_webauthn(stored.value);
      if (existing && existing->credential_id == checked.value.credential.credential_id)
        return answer->finish(Answer::failure(Fault::duplicate, "that credential is registered already"));
    }
    const auto key = self->_new_key(user_id, FactorKind::webauthn);
    if (!key) return answer->finish(Answer::failure(Fault::failed, "no randomness for an ID"));
    auto record = std::make_shared<WebAuthnRecord>();
    record->created = self->_wall.unix_ms() / 1000;
    record->name = name;
    record->credential_id = checked.value.credential.credential_id;
    record->key = checked.value.credential.key;
    record->sign_count = checked.value.sign_count;
    record->backup_eligible = checked.value.backup_eligible;
    record->backed_up = checked.value.backed_up;
    record->aaguid = checked.value.credential.aaguid;
    self->_calls.put_settled(kTable, *key, encode(*record), 0, executor, [=](store::Write written) {
      if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
      self->_record(actor, "factor.webauthn.register", user_id, *key, executor, [=] { answer->finish(Answer::success(info_of(*key, *record))); });
    });
  });
}

void Factors::webauthn_credentials(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const {
  using Answer = Outcome<std::vector<std::string>>;
  auto answer = answering<std::vector<std::string>>(deadline, executor, std::move(done), kReadLate);
  _records(std::move(user_id), FactorKind::webauthn, executor, [answer](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    std::vector<std::string> out;
    for (const auto& stored : records.value)
      if (const auto credential = decode_webauthn(stored.value)) out.push_back(credential->credential_id);
    answer->finish(Answer::success(std::move(out)));
  });
}

void Factors::webauthn_check(std::string user_id, webauthn::Expected expected, std::string credential_id, Bytes client_data_json, Bytes authenticator_data,
                             Bytes signature, Deadline deadline, Executor executor, Done<Outcome<webauthn::Asserted>> done) {
  using Answer = Outcome<webauthn::Asserted>;
  auto answer = answering<webauthn::Asserted>(deadline, executor, std::move(done), kReadLate);
  auto self = shared_from_this();
  _records(std::move(user_id), FactorKind::webauthn, executor, [=](Outcome<std::vector<Stored>> records) {
    if (!records.ok()) return answer->finish(Answer::from(records));
    for (const auto& stored : records.value) {
      auto record = decode_webauthn(stored.value);
      if (!record || record->credential_id != credential_id) continue;
      const webauthn::Credential credential{record->credential_id, record->key, record->sign_count, record->backup_eligible};
      const auto checked = webauthn::check_assertion(expected, credential, client_data_json, authenticator_data, signature);
      if (!checked.ok()) return answer->finish(checked);
      record->sign_count = checked.value.sign_count;
      record->backed_up = checked.value.backed_up;
      record->last_used = self->_wall.unix_ms() / 1000;
      return self->_calls.put_settled(kTable, stored.key, encode(*record), stored.version, executor, [answer, checked](store::Write written) {
        if (written.ok()) return answer->finish(checked);
        // Another sign-in used this credential between the read and the write.
        if (written.error == store::StoreError::conflict) return answer->finish(Answer::failure(Fault::refused, "the credential was used at the same moment"));
        answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
      });
    }
    answer->finish(Answer::failure(Fault::refused, "no such credential for this user"));
  });
}

void Factors::webauthn_rename(audit::Actor actor, std::string user_id, std::string factor_id, std::string name, Deadline deadline, Executor executor,
                              Done<Outcome<FactorInfo>> done) {
  using Answer = Outcome<FactorInfo>;
  auto answer = answering<FactorInfo>(deadline, executor, std::move(done), kChangeLate);
  if (name.empty() || !directory::printable(name, kMostCredentialNameBytes))
    return answer->finish(Answer::failure(Fault::invalid, "a credential's name is 1 to 64 printable bytes"));
  const auto prefix = user_id + "/webauthn/";
  if (factor_id.compare(0, prefix.size(), prefix) != 0) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));
  auto self = shared_from_this();
  _calls.get_settled(kTable, factor_id, executor, [=](Outcome<std::optional<store::Record>> stored) {
    if (!stored.ok()) return answer->finish(Answer::from(stored));
    auto record = stored.value ? decode_webauthn(stored.value->value) : std::nullopt;
    if (!record) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));
    record->name = name;
    auto kept = std::make_shared<WebAuthnRecord>(std::move(*record));
    self->_calls.put_settled(kTable, factor_id, encode(*kept), stored.value->version, executor, [=](store::Write written) {
      if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
      self->_record(actor, "factor.webauthn.rename", user_id, factor_id, executor, [=] { answer->finish(Answer::success(info_of(factor_id, *kept))); });
    });
  });
}

void Factors::remove(audit::Actor actor, std::string user_id, std::string factor_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  const auto prefix = user_id + "/";
  if (factor_id.compare(0, prefix.size(), prefix) != 0) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));
  auto self = shared_from_this();
  _calls.get_settled(kTable, factor_id, executor, [=](Outcome<std::optional<store::Record>> stored) {
    if (!stored.ok()) return answer->finish(Answer::from(stored));
    if (!stored.value) return answer->finish(Answer::failure(Fault::not_found, "no such factor"));
    self->_calls.remove_settled(kTable, factor_id, std::nullopt, executor, [=](store::Write removed) {
      if (!removed.ok()) return answer->finish(Answer::failure(directory::fault_of(removed.error), removed.message));
      self->_record(actor, "factor.remove", user_id, factor_id, executor, [answer] { answer->finish(Answer::success()); });
    });
  });
}

void Factors::forget(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Status> done) {
  auto answer = Completion<Status>::start(deadline, executor, std::move(done),
                                          [] { return Status::failure("the factors did not answer within the deadline; they may yet be removed"); });
  auto self = shared_from_this();
  _records(user_id, std::nullopt, executor, [=](Outcome<std::vector<Stored>> all) {
    if (!all.ok()) return answer->finish(Status::failure("cannot read the factors: " + all.message));
    if (all.value.empty()) return answer->finish(Status::success());
    const auto count = all.value.size();
    auto failed = std::make_shared<std::string>();
    in_turn<Stored>(
        std::make_shared<std::vector<Stored>>(std::move(all.value)), 0,
        [=](const Stored& stored, std::function<void()> next) {
          self->_calls.remove_settled(kTable, stored.key, std::nullopt, executor, [failed, next](store::Write removed) {
            if (!removed.ok() && removed.error != store::StoreError::removed) *failed = removed.message;
            next();
          });
        },
        [=] {
          self->_record(actor, "factor.reset", user_id, std::to_string(count) + " removed", executor,
                        [answer, failed] { answer->finish(failed->empty() ? Status::success() : Status::failure("cannot remove every factor: " + *failed)); });
        });
  });
}

void Factors::_records(std::string user_id, std::optional<FactorKind> kind, Executor executor, Done<Outcome<std::vector<Stored>>> done) const {
  using Answer = Outcome<std::vector<Stored>>;
  const auto prefix = user_id + "/" + (kind ? std::string(kind_name(*kind)) + "/" : "");
  _calls.list_settled(kTable, std::move(executor), [prefix, done = std::move(done)](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return done(Answer::from(records));
    std::vector<Stored> out;
    for (auto& record : records.value) {
      if (record.key.compare(0, prefix.size(), prefix) != 0) continue;
      out.push_back(Stored{std::move(record.key), record.version, std::move(record.value)});
    }
    done(Answer::success(std::move(out)));
  });
}

std::optional<std::string> Factors::_new_key(std::string_view user_id, FactorKind kind) {
  const auto instance = dannan::identity::random_bytes(8);
  if (instance.empty()) return std::nullopt;
  return std::string(user_id) + "/" + std::string(kind_name(kind)) + "/" + dannan::identity::hex(instance);
}

void Factors::_record(const audit::Actor& actor, std::string action, std::string user_id, std::string detail, Executor executor,
                      std::function<void()> then) const {
  // A failure is logged by the audit log itself; the change has been made.
  _audit_log->record(audit::Event{std::move(action), actor.id, std::move(user_id), actor.source, std::move(detail)}, kAuditDeadline, std::move(executor),
                     [then = std::move(then)](Status) { then(); });
}

}  // namespace lugh::authn
