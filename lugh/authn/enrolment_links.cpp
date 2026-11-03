//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/enrolment_links.h"

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"
#include "lugh/core/encoding.h"

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr const char* kPrefix = "enrol/";
const std::string kFirstSignIn = "first-sign-in/";

}  // namespace

EnrolmentLinks::EnrolmentLinks(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
                               std::shared_ptr<audit::AuditLog> audit, std::chrono::seconds lifetime)
    : _store(std::move(store)), _wall(wall), _directory(std::move(directory)), _audit(std::move(audit)), _lifetime(lifetime) {}

Task<Outcome<Secret>> EnrolmentLinks::issue(audit::Actor actor, std::string user_id) {
  using Answer = Outcome<Secret>;
  const auto user = co_await _directory->user(user_id);
  if (!user) co_return Answer::failure(Fault::not_found, "no such user");
  if (user->kind != directory::Kind::person) co_return Answer::failure(Fault::refused, "a service does not enrol");
  if (user->disabled) co_return Answer::failure(Fault::refused, "the user is disabled");
  if (user->enrolled) co_return Answer::failure(Fault::refused, "the user is enrolled; reset their factors first");

  for (const auto& record : co_await _store->list(kTable)) {
    if (record.key.rfind(kPrefix, 0) != 0) continue;
    const auto link = decode(record.value);
    if (link && link->user_id == user_id) co_await _store->remove(kTable, record.key, record.version);
  }

  const auto raw = secure_random(kTokenBytes);
  auto token = text_secret(encoding::base64url(raw));

  Link link;
  link.user_id = user_id;
  link.issued = (_wall.unix_ms() / 1000);
  link.expires = link.issued + static_cast<std::uint64_t>(_lifetime.count());

  const auto written = co_await _store->put(kTable, *_key(token), encode(link), 0);
  if (!written.ok()) co_return Answer::failure(directory::fault_of(written.error), written.message);
  co_await _audit->record(audit::Event{"enrolment.issue", actor.id, link.user_id, actor.source, "expires " + std::to_string(link.expires)});
  co_return Answer::success(std::move(token));
}

Task<Outcome<std::string>> EnrolmentLinks::peek(Secret token) const {
  using Answer = Outcome<std::string>;
  const auto key = _key(token);
  if (!key) co_return Answer::failure(Fault::not_found, "no such link");
  const auto live = co_await _live(*key);
  if (!live.ok()) co_return Answer::from(live);
  co_return Answer::success(live.value.first.user_id);
}

Task<Outcome<EnrolmentLinks::Link>> EnrolmentLinks::link(Secret token) const {
  using Answer = Outcome<Link>;
  const auto key = _key(token);
  if (!key) co_return Answer::failure(Fault::not_found, "no such link");
  const auto live = co_await _live(*key);
  if (!live.ok()) co_return Answer::from(live);
  co_return Answer::success(live.value.first);
}

Task<Outcome<std::string>> EnrolmentLinks::spend(Secret token, audit::Actor actor) {
  using Answer = Outcome<std::string>;
  const auto key = _key(token);
  if (!key) co_return Answer::failure(Fault::not_found, "no such link");
  const auto live = co_await _live(*key);
  if (!live.ok()) co_return Answer::from(live);
  const auto& [link, version] = live.value;

  const auto removed = co_await _store->remove(kTable, *key, version);
  if (!removed.ok()) {
    if (removed.error == store::StoreError::conflict || removed.error == store::StoreError::removed) {
      co_return Answer::failure(Fault::not_found, "no such link");
    }
    co_return Answer::failure(directory::fault_of(removed.error), removed.message);
  }
  co_await _audit->record(audit::Event{"enrolment.redeem", actor.id, link.user_id, actor.source, {}});
  co_return Answer::success(link.user_id);
}

Task<Outcome<>> EnrolmentLinks::first_sign_in_allow(audit::Actor actor, std::string user_id) {
  Link link;
  link.user_id = std::move(user_id);
  link.issued = (_wall.unix_ms() / 1000);
  // Until it is spent.
  link.expires = UINT64_MAX;
  const auto written = co_await _store->put(kTable, kFirstSignIn + link.user_id, encode(link), 0);
  if (!written.ok()) co_return Outcome<>::failure(directory::fault_of(written.error), written.message);
  co_await _audit->record(audit::Event{"enrolment.first_sign_in", actor.id, link.user_id, actor.source, {}});
  co_return Outcome<>::success();
}

Task<bool> EnrolmentLinks::first_sign_in_allowed(std::string user_id) const {
  const auto record = co_await _store->get(kTable, kFirstSignIn + user_id);
  const auto link = record ? decode(record->value) : std::nullopt;
  co_return link && link->user_id == user_id;
}

Task<void> EnrolmentLinks::first_sign_in_spend(std::string user_id) {
  const auto key = kFirstSignIn + user_id;
  if (co_await _store->get(kTable, key)) co_await _store->remove(kTable, key);
}

SecureBuffer EnrolmentLinks::encode(const Link& link) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.string(link.user_id);
  writer.u64(link.issued);
  writer.u64(link.expires);
  return writer.take();
}

std::optional<EnrolmentLinks::Link> EnrolmentLinks::decode(std::span<const unsigned char> value) {
  return decode_whole<Link>(value, [](dannan::net::Reader& reader) -> std::optional<Link> {
    if (reader.u8() != kFormat) return std::nullopt;
    Link link;
    link.user_id = reader.string(kMostFieldBytes);
    link.issued = reader.u64();
    link.expires = reader.u64();
    if (link.user_id.empty()) return std::nullopt;
    return link;
  });
}

std::optional<std::string> EnrolmentLinks::_key(const Secret& token) {
  // Exactly what issue() makes: 43 base64url characters.
  const auto text = secret_text(token);
  if (text.size() != (kTokenBytes * 4 + 2) / 3) return std::nullopt;
  for (const char c : text) {
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return std::nullopt;
  }
  return std::string(kPrefix) + dannan::identity::hex(dannan::identity::sha256(byte_span(text)).bytes);
}

Task<Outcome<std::pair<EnrolmentLinks::Link, std::uint64_t>>> EnrolmentLinks::_live(std::string key) const {
  using Answer = Outcome<std::pair<Link, std::uint64_t>>;
  const auto record = co_await _store->get(kTable, std::move(key));
  auto link = record ? decode(record->value) : std::nullopt;
  // An expired link is no different, to its holder, from one that never was.
  if (!link || (_wall.unix_ms() / 1000) >= link->expires) co_return Answer::failure(Fault::not_found, "no such link");
  co_return Answer::success(std::make_pair(std::move(*link), record->version));
}

}  // namespace lugh::authn
