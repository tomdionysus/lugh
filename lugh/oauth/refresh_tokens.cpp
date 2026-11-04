//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/refresh_tokens.h"

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"
#include "lugh/directory/directory.h"
#include "lugh/scopes/scope.h"

namespace lugh::oauth {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::size_t kFamilyBytes = 16;
constexpr std::size_t kSecretBytes = 32;
constexpr Deadline kStepDeadline = std::chrono::seconds(30);
constexpr const char* kLate = "the refresh tokens did not answer within the deadline";
constexpr const char* kNotGood = "the refresh token is not good";

std::string hash_of(std::string_view secret) { return dannan::identity::hex(dannan::identity::sha256(byte_span(secret))); }

std::string key_of(std::string_view family) { return "refresh/" + std::string(family); }

void write_strings(SecureWriter& writer, const std::vector<std::string>& list) {
  writer.u32(static_cast<std::uint32_t>(list.size()));
  for (const auto& one : list) writer.string(one);
}

std::vector<std::string> read_strings(dannan::net::Reader& reader) {
  const auto count = reader.u32();
  if (count > 1024) throw dannan::net::DecodeError("too many");
  std::vector<std::string> out;
  for (std::uint32_t i = 0; i < count; ++i) out.push_back(reader.string(scopes::kMostScopeBytes));
  return out;
}

}  // namespace

RefreshTokens::RefreshTokens(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<session::Sessions> sessions,
                             std::shared_ptr<audit::AuditLog> audit)
    : _calls(std::move(store)), _wall(wall), _sessions(std::move(sessions)), _audit(std::move(audit)) {}

SecureBuffer RefreshTokens::encode(const Family& family) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.string(family.client_id);
  writer.string(family.user_id);
  writer.string(family.sid);
  write_strings(writer, family.scopes);
  writer.u8(static_cast<std::uint8_t>(family.acr));
  write_strings(writer, family.amr);
  writer.u64(family.auth_time);
  writer.u64(family.created);
  writer.u64(family.last_used);
  writer.u32(family.idle_seconds);
  writer.u32(family.absolute_seconds);
  writer.string(family.current);
  writer.u8(family.revoked ? 1 : 0);
  return writer.take();
}

std::optional<Family> RefreshTokens::decode(std::span<const unsigned char> value) {
  return decode_whole<Family>(value, [](dannan::net::Reader& reader) -> std::optional<Family> {
    if (reader.u8() != kFormat) return std::nullopt;
    Family family;
    family.client_id = reader.string(kMostFieldBytes);
    family.user_id = reader.string(kMostFieldBytes);
    family.sid = reader.string(kMostFieldBytes);
    family.scopes = read_strings(reader);
    const auto acr = reader.u8();
    if (acr < static_cast<std::uint8_t>(authn::Assurance::pwd) || acr > static_cast<std::uint8_t>(authn::Assurance::phr)) return std::nullopt;
    family.acr = static_cast<authn::Assurance>(acr);
    family.amr = read_strings(reader);
    family.auth_time = reader.u64();
    family.created = reader.u64();
    family.last_used = reader.u64();
    family.idle_seconds = reader.u32();
    family.absolute_seconds = reader.u32();
    family.current = reader.string(64);
    const auto revoked = reader.u8();
    if (revoked > 1) return std::nullopt;
    family.revoked = revoked == 1;
    return family;
  });
}

std::optional<RefreshTokens::Parsed> RefreshTokens::_parse(std::string_view token) {
  if (token.rfind(kPrefix, 0) != 0 || token.size() > 128) return std::nullopt;
  const auto rest = token.substr(std::string_view(kPrefix).size());
  const auto dot = rest.find('.');
  if (dot == std::string_view::npos) return std::nullopt;
  const auto family = rest.substr(0, dot);
  const auto secret = rest.substr(dot + 1);
  const auto family_bytes = encoding::base64url_decode(family);
  const auto secret_bytes = encoding::base64url_decode(secret);
  if (!family_bytes || family_bytes->size() != kFamilyBytes || !secret_bytes || secret_bytes->size() != kSecretBytes) return std::nullopt;
  return Parsed{std::string(family), std::string(secret)};
}

bool RefreshTokens::_live(const Family& family) const {
  const auto now = _wall.unix_ms() / 1000;
  return !family.revoked && now < family.last_used + family.idle_seconds && now < family.created + family.absolute_seconds && _sessions->live_sid(family.sid);
}

void RefreshTokens::_read(std::string family, Executor executor, Done<Outcome<std::optional<Family>>> done) const {
  using Answer = Outcome<std::optional<Family>>;
  _calls.get_settled(kTable, key_of(family), std::move(executor), [family, done = std::move(done)](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    if (!record.value) return done(Answer::success(std::nullopt));
    auto decoded = decode(record.value->value);
    if (!decoded) return done(Answer::failure(Fault::failed, "a refresh token family does not decode"));
    decoded->id = family;
    decoded->version = record.value->version;
    done(Answer::success(std::move(decoded)));
  });
}

void RefreshTokens::_revoke(Family family, std::string why, Executor executor, std::function<void()> then) {
  if (family.revoked) return then();
  family.revoked = true;
  auto self = shared_from_this();
  // Written whatever the version now: a revocation is never lost to a race.
  _calls.put_settled(kTable, key_of(family.id), encode(family), std::nullopt, executor, [self, family, why, executor, then](store::Write) {
    self->_audit->record(audit::Event{"refresh.revoke", "lugh", family.user_id, {}, family.client_id + ": " + why}, kStepDeadline, executor,
                         [then](Status) { then(); });
  });
}

void RefreshTokens::issue(const apps::App& app, const CodeGrant& grant, std::vector<std::string> scopes, Deadline deadline, Executor executor,
                          Done<Outcome<std::string>> done) {
  using Answer = Outcome<std::string>;
  auto answer = answering<std::string>(deadline, executor, std::move(done), kLate);
  const auto now = _wall.unix_ms() / 1000;
  Family family;
  family.id = encoding::base64url(dannan::identity::random_bytes(kFamilyBytes));
  family.client_id = app.client_id;
  family.user_id = grant.user_id;
  family.sid = grant.sid;
  family.scopes = std::move(scopes);
  family.acr = grant.acr;
  family.amr = grant.amr;
  family.auth_time = grant.auth_time;
  family.created = family.last_used = now;
  family.idle_seconds = app.refresh_idle_seconds;
  family.absolute_seconds = app.refresh_absolute_seconds;
  const auto secret = encoding::base64url(secure_random(kSecretBytes));
  family.current = hash_of(secret);
  const auto token = std::string(kPrefix) + family.id + "." + secret;
  _calls.put_settled(kTable, key_of(family.id), encode(family), 0, executor, [answer, token](store::Write written) {
    if (!written.ok()) return answer->finish(Answer::failure(Fault::failed, written.message));
    answer->finish(Answer::success(token));
  });
}

void RefreshTokens::rotate(std::string token, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<Rotated>> done) {
  using Answer = Outcome<Rotated>;
  auto answer = answering<Rotated>(deadline, executor, std::move(done), kLate);
  const auto parsed = _parse(token);
  if (!parsed) return answer->finish(Answer::failure(Fault::refused, kNotGood));
  auto self = shared_from_this();
  _read(parsed->family, executor, [=](Outcome<std::optional<Family>> found) {
    if (!found.ok()) return answer->finish(Answer::from(found));
    if (!found.value || found.value->client_id != client_id) return answer->finish(Answer::failure(Fault::refused, kNotGood));
    auto family = std::move(*found.value);
    const auto presented = hash_of(parsed->secret);
    if (!dannan::identity::constant_time_equal(byte_span(presented), byte_span(family.current))) {
      // Not the newest: the token was copied, or a rotation's answer was lost. Either way the
      // family cannot be trusted.
      return self->_revoke(family, "a rotated refresh token was used again", executor, [answer] { answer->finish(Answer::failure(Fault::refused, kNotGood)); });
    }
    if (!self->_live(family)) return answer->finish(Answer::failure(Fault::refused, kNotGood));

    const auto version = family.version;
    const auto secret = encoding::base64url(secure_random(kSecretBytes));
    family.current = hash_of(secret);
    family.last_used = self->_wall.unix_ms() / 1000;
    self->_calls.put_settled(kTable, key_of(family.id), encode(family), version, executor, [=](store::Write written) mutable {
      if (!written.ok()) {
        // Another rotation of the same token won: this one is the reuse.
        if (written.error == store::StoreError::conflict) {
          return self->_revoke(family, "two rotations of one refresh token raced", executor,
                               [answer] { answer->finish(Answer::failure(Fault::refused, kNotGood)); });
        }
        return answer->finish(Answer::failure(Fault::failed, written.message));
      }
      family.version = written.version;
      answer->finish(Answer::success(Rotated{family, std::string(kPrefix) + family.id + "." + secret}));
    });
  });
}

void RefreshTokens::inspect(std::string token, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<std::optional<Family>>> done) const {
  using Answer = Outcome<std::optional<Family>>;
  auto answer = answering<std::optional<Family>>(deadline, executor, std::move(done), kLate);
  const auto parsed = _parse(token);
  if (!parsed) return answer->finish(Answer::success(std::nullopt));
  auto self = shared_from_this();
  _read(parsed->family, executor, [=](Answer found) {
    if (!found.ok()) return answer->finish(std::move(found));
    if (!found.value || found.value->client_id != client_id || !self->_live(*found.value) ||
        !dannan::identity::constant_time_equal(byte_span(hash_of(parsed->secret)), byte_span(found.value->current)))
      return answer->finish(Answer::success(std::nullopt));
    answer->finish(std::move(found));
  });
}

void RefreshTokens::revoke(audit::Actor actor, std::string token, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kLate);
  const auto parsed = _parse(token);
  if (!parsed) return answer->finish(Answer::success());
  auto self = shared_from_this();
  _read(parsed->family, executor, [=](Outcome<std::optional<Family>> found) {
    if (!found.ok()) return answer->finish(Answer::from(found));
    if (!found.value || found.value->client_id != client_id) return answer->finish(Answer::success());
    self->_revoke(*found.value, "revoked by the client from " + actor.source, executor, [answer] { answer->finish(Answer::success()); });
  });
}

}  // namespace lugh::oauth
