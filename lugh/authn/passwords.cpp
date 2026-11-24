//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/passwords.h"

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"
#include "lugh/core/steps.h"

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
      _calls(std::move(store)),
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

namespace {

constexpr const char* kChangeLate = "the passwords did not answer within the deadline; the change may yet be made";
constexpr const char* kCheckLate = "the password was not checked within the deadline";
constexpr Deadline kAuditDeadline = std::chrono::seconds(30);

}  // namespace

void Passwords::set(audit::Actor actor, directory::User user, Secret password, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  if (user.kind != directory::Kind::person) return answer->finish(Answer::failure(Fault::refused, "a service has no password"));
  if (const auto ok = acceptable(password, user); !ok.ok()) return answer->finish(ok);

  on_pool(
      _hashing, [params = _params, password = std::move(password)] { return hash_password(password.reveal(), params); }, executor,
      [self = shared_from_this(), answer, actor, user, executor](Result<PasswordHash> hashed) mutable {
        if (!hashed.ok) return answer->finish(Answer::failure(Fault::failed, hashed.error));
        self->_calls.put_settled(kTable, user.id, encode(Credential{std::move(hashed.value), (self->_wall.unix_ms() / 1000)}), std::nullopt, executor,
                                 [self, answer, actor, user, executor](store::Write written) {
                                   if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
                                   self->_record(audit::Event{"password.set", actor.id, user.id, actor.source, "version " + std::to_string(written.version)},
                                                 executor, [answer] { answer->finish(Answer::success()); });
                                 });
      });
}

void Passwords::verify(std::string user_id, Secret password, Deadline deadline, Executor executor, Done<Outcome<bool>> done) {
  using Answer = Outcome<bool>;
  auto answer = answering<bool>(deadline, executor, std::move(done), kCheckLate);
  // Held where every step can reach it: a Secret is not copied.
  auto held = std::make_shared<Secret>(std::move(password));
  auto self = shared_from_this();
  _calls.get_settled(kTable, user_id, executor, [=](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    auto credential = record.value ? decode(record.value->value) : std::nullopt;
    if (!credential) {
      // The same work as a real check, so the time taken says nothing about who exists.
      return on_pool(
          self->_hashing,
          [params = self->_params, salt = self->_decoy_salt, held] {
            (void)crypto::stretch(held->reveal(), salt, params, kPasswordHashBytes);
            return false;
          },
          executor, [answer](bool) { answer->finish(Answer::success(false)); });
    }

    // The match and, when the costs have moved, the new hash, in one trip to the pool.
    struct Checked {
      bool right = false;
      std::optional<PasswordHash> again;
    };
    const auto version = record.value->version;
    const auto changed = credential->changed;
    on_pool(
        self->_hashing,
        [params = self->_params, hash = std::move(credential->hash), held] {
          Checked out;
          const auto secret = held->reveal();
          out.right = verify_password(secret, hash);
          if (out.right && !same_costs(hash.costs, params)) {
            if (auto hashed = hash_password(secret, params); hashed.ok) out.again = std::move(hashed.value);
          }
          return out;
        },
        executor,
        [=](Checked checked) mutable {
          if (!checked.right) return answer->finish(Answer::success(false));
          if (!checked.again) return answer->finish(Answer::success(true));
          // Against the version just read: if the password changed in the meantime, the
          // newer one stands.
          self->_calls.put_settled(kTable, user_id, encode(Credential{std::move(*checked.again), changed}), version, executor,
                                   [self, answer, user_id](store::Write written) {
                                     if (written.ok()) self->_logger.info("password hash for " + user_id + " moved to the current costs");
                                     answer->finish(Answer::success(true));
                                   });
        });
  });
}

void Passwords::spend(Secret password, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kCheckLate);
  on_pool(
      _hashing,
      [params = _params, salt = _decoy_salt, password = std::move(password)] {
        (void)crypto::stretch(password.reveal(), salt, params, kPasswordHashBytes);
        return Outcome<>::success();
      },
      executor, [answer](Outcome<> spent) { answer->finish(std::move(spent)); });
}

void Passwords::has_password(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<bool>> done) const {
  using Answer = Outcome<bool>;
  auto answer = answering<bool>(deadline, executor, std::move(done), kCheckLate);
  _calls.get_settled(kTable, std::move(user_id), executor, [answer](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    answer->finish(Answer::success(record.value.has_value()));
  });
}

void Passwords::forget(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Status> done) {
  auto answer = Completion<Status>::start(deadline, executor, std::move(done),
                                          [] { return Status::failure("the passwords did not answer within the deadline; the password may yet be removed"); });
  auto self = shared_from_this();
  _calls.get_settled(kTable, user_id, executor, [=](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Status::failure("cannot read the password: " + record.message));
    if (!record.value) return answer->finish(Status::success());
    self->_calls.remove_settled(kTable, user_id, std::nullopt, executor, [=](store::Write removed) {
      if (!removed.ok()) return answer->finish(Status::failure("cannot remove the password: " + removed.message));
      self->_record(audit::Event{"password.remove", actor.id, user_id, actor.source, {}}, executor, [answer] { answer->finish(Status::success()); });
    });
  });
}

void Passwords::_record(audit::Event event, Executor executor, std::function<void()> then) {
  // A failure is logged by the audit log itself; the change has been made.
  _audit->record(std::move(event), kAuditDeadline, std::move(executor), [then = std::move(then)](Status) { then(); });
}

}  // namespace lugh::authn
