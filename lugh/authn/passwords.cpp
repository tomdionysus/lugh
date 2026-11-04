//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/passwords.h"

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;

struct Credential {
  PasswordHash hash;
  std::uint64_t changed = 0;
};

SecureBuffer encode(const Credential& credential) {
  SecureWriter writer;
  writer.u8(kFormat);
  write_password_hash(writer, credential.hash);
  writer.u64(credential.changed);
  return writer.take();
}

std::optional<Credential> decode(std::span<const unsigned char> value) {
  return decode_whole<Credential>(value, [](dannan::net::Reader& reader) -> std::optional<Credential> {
    if (reader.u8() != kFormat) return std::nullopt;
    auto hash = read_password_hash(reader);
    const auto changed = reader.u64();
    if (!hash) return std::nullopt;
    return Credential{std::move(*hash), changed};
  });
}

// Characters, counting each UTF-8 lead byte; what follows a lead byte is not counted.
std::size_t characters(std::string_view text) {
  std::size_t count = 0;
  for (const char c : text) {
    if ((static_cast<unsigned char>(c) & 0xc0) != 0x80) ++count;
  }
  return count;
}

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// ASCII case folded, without a copy of the password outside locked memory.
bool same_folded(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  unsigned char differ = 0;
  for (std::size_t i = 0; i < a.size(); ++i) differ |= static_cast<unsigned char>(lower(a[i]) ^ lower(b[i]));
  return differ == 0;
}

}  // namespace

Task<Result<BreachedPasswords>> BreachedPasswords::load(const system::Files& files, std::string path) {
  using Answer = Result<BreachedPasswords>;
  const auto read = co_await files.read(std::move(path), kMostFileBytes);
  if (!read.ok) co_return Answer::failure("authn.breached_passwords: " + read.error);
  co_return Answer::success(from_text(read.value));
}

BreachedPasswords BreachedPasswords::from_text(std::span<const unsigned char> text) {
  BreachedPasswords out;
  std::size_t start = 0;
  while (start < text.size()) {
    auto end = start;
    while (end < text.size() && text[end] != '\n') ++end;
    auto line = text.subspan(start, end - start);
    if (!line.empty() && line.back() == '\r') line = line.first(line.size() - 1);
    if (!line.empty() && line.front() != '#') out._hashes.insert(_fold_and_hash(line));
    start = end + 1;
  }
  return out;
}

bool BreachedPasswords::contains(std::span<const unsigned char> password) const { return !_hashes.empty() && _hashes.count(_fold_and_hash(password)) != 0; }

std::array<unsigned char, 32> BreachedPasswords::_fold_and_hash(std::span<const unsigned char> password) {
  SecureBuffer folded(password.begin(), password.end());
  for (auto& byte : folded) byte = static_cast<unsigned char>(lower(static_cast<char>(byte)));
  return dannan::identity::sha256(folded).bytes;
}

Passwords::Passwords(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall,
                     std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs params, PasswordRules rules, BreachedPasswords breached)
    : _logger(std::move(log), "passwords"),
      _store(std::move(store)),
      _wall(wall),
      _audit(std::move(audit)),
      _hashing(std::move(hashing)),
      _params(params),
      _rules(rules),
      _breached(std::move(breached)),
      _decoy_salt(kPasswordSaltBytes, 0x5c) {}

Outcome<> Passwords::acceptable(const Secret& password, const directory::User& user) const {
  using Answer = Outcome<>;
  const auto text = secret_text(password);
  if (characters(text) < _rules.least_characters) {
    return Answer::failure(Fault::invalid, "a password is at least " + std::to_string(_rules.least_characters) + " characters");
  }
  if (text.size() > _rules.most_bytes) return Answer::failure(Fault::invalid, "a password is at most " + std::to_string(_rules.most_bytes) + " bytes");
  if (same_folded(text, user.name) || (!user.email.empty() && same_folded(text, user.email))) {
    return Answer::failure(Fault::invalid, "a password cannot be the user's own name or address");
  }
  if (_breached.contains(byte_span(text))) return Answer::failure(Fault::invalid, "that password is on the list of breached passwords");
  return Answer::success();
}

Task<Outcome<>> Passwords::set(audit::Actor actor, directory::User user, Secret password) {
  using Answer = Outcome<>;
  if (user.kind != directory::Kind::person) co_return Answer::failure(Fault::refused, "a service has no password");
  if (const auto ok = acceptable(password, user); !ok.ok()) co_return ok;

  auto hashed = co_await offload(_hashing, [params = _params, password = std::move(password)] { return hash_password(password.reveal(), params); });
  if (!hashed.ok) co_return Answer::failure(Fault::failed, hashed.error);

  const auto written = co_await _store->put(kTable, user.id, encode(Credential{std::move(hashed.value), (_wall.unix_ms() / 1000)}));
  if (!written.ok()) co_return Answer::failure(directory::fault_of(written.error), written.message);
  co_await _audit->record(audit::Event{"password.set", actor.id, user.id, actor.source, "version " + std::to_string(written.version)});
  co_return Answer::success();
}

Task<bool> Passwords::verify(std::string user_id, Secret password) {
  const auto record = co_await _store->get(kTable, user_id);
  auto credential = record ? decode(record->value) : std::nullopt;
  if (!credential) {
    co_await spend(std::move(password));
    co_return false;
  }

  // The match and, when the costs have moved, the new hash, in one trip to the pool.
  struct Checked {
    bool right = false;
    std::optional<PasswordHash> again;
  };
  auto checked = co_await offload(_hashing, [params = _params, hash = std::move(credential->hash), password = std::move(password)] {
    Checked out;
    const auto secret = password.reveal();
    out.right = verify_password(secret, hash);
    if (out.right && !same_costs(hash.params, params)) {
      if (auto hashed = hash_password(secret, params); hashed.ok) out.again = std::move(hashed.value);
    }
    return out;
  });
  if (!checked.right) co_return false;

  if (checked.again) {
    // Against the version just read: if the password changed in the meantime, the newer
    // one stands.
    const auto written = co_await _store->put(kTable, user_id, encode(Credential{std::move(*checked.again), credential->changed}), record->version);
    if (written.ok()) _logger.info("password hash for " + user_id + " moved to the current costs");
  }
  co_return true;
}

Task<void> Passwords::spend(Secret password) {
  co_await offload(_hashing, [params = _params, salt = _decoy_salt, password = std::move(password)] {
    (void)crypto::stretch(password.reveal(), salt, params, kPasswordHashBytes);
  });
}

Task<bool> Passwords::has_password(std::string user_id) const { co_return (co_await _store->get(kTable, std::move(user_id))).has_value(); }

Task<Status> Passwords::forget(audit::Actor actor, std::string user_id) {
  if (!co_await _store->get(kTable, user_id)) co_return Status::success();
  const auto removed = co_await _store->remove(kTable, user_id);
  if (!removed.ok()) co_return Status::failure("cannot remove the password: " + removed.message);
  co_await _audit->record(audit::Event{"password.remove", actor.id, user_id, actor.source, {}});
  co_return Status::success();
}

}  // namespace lugh::authn
