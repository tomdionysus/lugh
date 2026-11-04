//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/tokens/signing_keys.h"

#include <algorithm>
#include <stdexcept>

#include "lugh/core/codec.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"

namespace lugh::tokens {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::size_t kKidBytes = 16;
constexpr std::size_t kMostPkcs8Bytes = 4096;
constexpr const char* kChangeLate = "the signing keys did not answer within the deadline; the change may yet be made";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);
constexpr std::array kAlgorithms{SigningAlgorithm::es256, SigningAlgorithm::ed25519};

}  // namespace

SigningKeys::SigningKeys(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<audit::AuditLog> audit,
                         Settings settings)
    : _calls(std::move(store)), _wall(wall), _audit(std::move(audit)), _settings(settings) {}

SecureBuffer SigningKeys::encode(const Record& record) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.u8(static_cast<std::uint8_t>(record.algorithm));
  writer.bytes(record.pkcs8);
  writer.u64(record.created);
  writer.u64(record.active_from);
  writer.u64(record.retired_at);
  return writer.take();
}

std::optional<SigningKeys::Record> SigningKeys::decode(std::span<const unsigned char> value) {
  return decode_whole<Record>(value, [](dannan::net::Reader& reader) -> std::optional<Record> {
    if (reader.u8() != kFormat) return std::nullopt;
    const auto algorithm = reader.u8();
    if (algorithm > static_cast<std::uint8_t>(SigningAlgorithm::ed25519)) return std::nullopt;
    Record record;
    record.algorithm = static_cast<SigningAlgorithm>(algorithm);
    // The private key is read in place and copied straight into secure memory.
    const auto pkcs8 = reader.view_bytes(kMostPkcs8Bytes);
    record.pkcs8 = SecureBuffer(pkcs8.begin(), pkcs8.end());
    record.created = reader.u64();
    record.active_from = reader.u64();
    record.retired_at = reader.u64();
    return record;
  });
}

void SigningKeys::open(Deadline deadline, Executor executor, Done<Status> done) {
  auto answer =
      Completion<Status>::start(deadline, executor, std::move(done), [] { return Status::failure("the signing keys were not read within the deadline"); });
  auto self = shared_from_this();
  _calls.list_settled(kTable, executor, [=](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return answer->finish(Status::failure(records.message));
    std::vector<Held> held;
    for (const auto& record : records.value) {
      const auto decoded = decode(record.value);
      if (!decoded) return answer->finish(Status::failure("the signing key " + record.key + " does not decode"));
      try {
        auto key = std::make_shared<const SigningKey>(SigningKey::from_pkcs8(decoded->pkcs8));
        if (key->algorithm() != decoded->algorithm) return answer->finish(Status::failure("the signing key " + record.key + " is not the algorithm it says"));
        held.push_back(
            Held{KeyInfo{record.key, decoded->algorithm, decoded->created, decoded->active_from, decoded->retired_at}, record.version, key, key->public_key()});
      } catch (const std::exception& e) {
        return answer->finish(Status::failure("the signing key " + record.key + " cannot be read: " + e.what()));
      }
    }
    {
      dannan::contract::Lock state(self->_mutex);
      self->_held = std::move(held);
    }
    // A new cluster's first start: a key of each algorithm, signing at once, since there is
    // nothing yet that could have fetched an older JWKS.
    auto missing = std::make_shared<std::vector<SigningAlgorithm>>();
    for (const auto algorithm : kAlgorithms) {
      if (!self->_newest(algorithm)) missing->push_back(algorithm);
    }
    auto failed = std::make_shared<std::optional<std::string>>();
    in_turn<SigningAlgorithm>(
        missing, 0,
        [=](const SigningAlgorithm& algorithm, std::function<void()> next) {
          if (*failed) return next();
          self->_make(audit::Actor{"lugh", ""}, algorithm, self->_now(), executor, [=](Outcome<KeyInfo> made) {
            if (!made.ok()) *failed = made.message;
            next();
          });
        },
        [=] { answer->finish(*failed ? Status::failure(**failed) : Status::success()); });
  });
}

std::optional<SigningKeys::Held> SigningKeys::_newest(SigningAlgorithm algorithm) const {
  dannan::contract::Lock state(_mutex);
  std::optional<Held> out;
  for (const auto& one : _held) {
    if (one.info.algorithm != algorithm || one.info.retired_at != 0) continue;
    if (!out || one.info.active_from > out->info.active_from) out = one;
  }
  return out;
}

std::optional<Signer> SigningKeys::signer(SigningAlgorithm algorithm) const {
  const auto now = _now();
  dannan::contract::Lock state(_mutex);
  const Held* best = nullptr;
  for (const auto& one : _held) {
    if (one.info.algorithm != algorithm || one.info.active_from > now) continue;
    if (one.info.retired_at != 0 && one.info.retired_at <= now) continue;
    if (!best || one.info.active_from > best->info.active_from) best = &one;
  }
  if (!best) return std::nullopt;
  return Signer{best->info.kid, best->key};
}

std::vector<VerifyKey> SigningKeys::published() const {
  const auto now = _now();
  dannan::contract::Lock state(_mutex);
  std::vector<VerifyKey> out;
  for (const auto& one : _held) {
    if (one.info.retired_at != 0 && one.info.retired_at <= now) continue;
    out.push_back(VerifyKey{one.info.kid, one.info.algorithm, one.public_key});
  }
  // In one order, whatever order the store keeps them in, so the document is the same at
  // every start.
  std::sort(out.begin(), out.end(), [](const VerifyKey& a, const VerifyKey& b) { return a.kid < b.kid; });
  return out;
}

boost::json::object SigningKeys::jwks() const {
  boost::json::array keys;
  for (const auto& key : published()) {
    if (const auto jwk = public_jwk(key)) keys.push_back(*jwk);
  }
  return boost::json::object{{"keys", std::move(keys)}};
}

std::vector<KeyInfo> SigningKeys::keys() const {
  std::vector<KeyInfo> out;
  {
    dannan::contract::Lock state(_mutex);
    for (const auto& one : _held) out.push_back(one.info);
  }
  std::sort(out.begin(), out.end(), [](const KeyInfo& a, const KeyInfo& b) { return a.created != b.created ? a.created > b.created : a.kid > b.kid; });
  return out;
}

void SigningKeys::_make(audit::Actor actor, SigningAlgorithm algorithm, std::uint64_t active_from, Executor executor, Done<Outcome<KeyInfo>> done) {
  using Answer = Outcome<KeyInfo>;
  std::shared_ptr<const SigningKey> key;
  Record record;
  try {
    key = std::make_shared<const SigningKey>(SigningKey::generate(algorithm));
    const auto pkcs8 = key->to_pkcs8();
    record.pkcs8 = SecureBuffer(pkcs8.reveal().begin(), pkcs8.reveal().end());
  } catch (const std::exception& e) {
    return done(Answer::failure(Fault::failed, std::string("no signing key could be made: ") + e.what()));
  }
  const auto id = dannan::identity::random_bytes(kKidBytes);
  if (id.empty()) return done(Answer::failure(Fault::failed, "no randomness for a kid"));
  record.algorithm = algorithm;
  record.created = _now();
  record.active_from = active_from;
  const KeyInfo info{encoding::base64url(id), algorithm, record.created, record.active_from, 0};

  auto self = shared_from_this();
  _calls.put_settled(kTable, info.kid, encode(record), 0, executor, [=](store::Write written) {
    if (!written.ok()) return done(Answer::failure(Fault::failed, written.message));
    {
      dannan::contract::Lock state(self->_mutex);
      self->_held.push_back(Held{info, written.version, key, key->public_key()});
    }
    self->_audit->record(audit::Event{"key.create", actor.id, info.kid, actor.source,
                                      std::string(dannan::identity::algorithm_name(algorithm)) + ", signing from " + std::to_string(info.active_from)},
                         kStepDeadline, executor, [done, info](Status) { done(Answer::success(info)); });
  });
}

void SigningKeys::rotate(audit::Actor actor, SigningAlgorithm algorithm, Deadline deadline, Executor executor, Done<Outcome<KeyInfo>> done) {
  using Answer = Outcome<KeyInfo>;
  auto answer = answering<KeyInfo>(deadline, executor, std::move(done), kChangeLate);
  const auto current = _newest(algorithm);
  const auto active_from = _now() + static_cast<std::uint64_t>(_settings.lead.count());
  auto self = shared_from_this();
  _make(actor, algorithm, active_from, executor, [=](Answer made) {
    if (!made.ok() || !current) return answer->finish(std::move(made));
    // The key before stays published until every token it signed has expired.
    Record retired;
    retired.algorithm = algorithm;
    const auto pkcs8 = current->key->to_pkcs8();
    retired.pkcs8 = SecureBuffer(pkcs8.reveal().begin(), pkcs8.reveal().end());
    retired.created = current->info.created;
    retired.active_from = current->info.active_from;
    retired.retired_at = active_from + static_cast<std::uint64_t>(self->_settings.retire_after.count());
    self->_calls.put_settled(kTable, current->info.kid, encode(retired), current->version, executor, [=](store::Write written) {
      if (!written.ok())
        return answer->finish(Answer::failure(
            Fault::failed, "the new key " + made.value.kid + " was made, but " + current->info.kid + " could not be marked retired: " + written.message));
      {
        dannan::contract::Lock state(self->_mutex);
        for (auto& one : self->_held) {
          if (one.info.kid != current->info.kid) continue;
          one.info.retired_at = retired.retired_at;
          one.version = written.version;
        }
      }
      self->_audit->record(
          audit::Event{"key.rotate", actor.id, made.value.kid, actor.source, current->info.kid + " retires at " + std::to_string(retired.retired_at)},
          kStepDeadline, executor, [answer, made](Status) { answer->finish(made); });
    });
  });
}

void SigningKeys::rotate_due(Deadline deadline, Executor executor, Done<Status> done) {
  auto answer =
      Completion<Status>::start(deadline, executor, std::move(done), [] { return Status::failure("the key rotation did not finish within the deadline"); });
  const auto now = _now();
  auto due = std::make_shared<std::vector<SigningAlgorithm>>();
  for (const auto algorithm : kAlgorithms) {
    const auto newest = _newest(algorithm);
    if (newest && now >= newest->info.active_from + static_cast<std::uint64_t>(_settings.rotate_every.count())) due->push_back(algorithm);
  }
  auto self = shared_from_this();
  auto failed = std::make_shared<std::optional<std::string>>();
  in_turn<SigningAlgorithm>(
      due, 0,
      [=](const SigningAlgorithm& algorithm, std::function<void()> next) {
        if (*failed) return next();
        self->rotate(audit::Actor{"lugh", ""}, algorithm, kStepDeadline, executor, [=](Outcome<KeyInfo> made) {
          if (!made.ok()) *failed = made.message;
          next();
        });
      },
      [=] { answer->finish(*failed ? Status::failure(**failed) : Status::success()); });
}

}  // namespace lugh::tokens
