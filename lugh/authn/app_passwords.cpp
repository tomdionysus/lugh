//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/app_passwords.h"

#include <algorithm>
#include <boost/asio/ip/address.hpp>

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"
#include "lugh/directory/records.h"
#include "lugh/scopes/scope.h"

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::size_t kPasswordBytes = 20;
constexpr std::size_t kInstanceBytes = 8;
constexpr const char* kWrong = "not an app password of this user's";
constexpr const char* kReadLate = "the app passwords were not read within the deadline";
constexpr const char* kChangeLate = "the app passwords did not answer within the deadline; the change may yet be made";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

void write_strings(SecureWriter& writer, const std::vector<std::string>& list) {
  writer.u32(static_cast<std::uint32_t>(list.size()));
  for (const auto& one : list) writer.string(one);
}

std::vector<std::string> read_strings(dannan::net::Reader& reader, std::size_t most) {
  const auto count = reader.u32();
  if (count > most) throw dannan::net::DecodeError("too many");
  std::vector<std::string> out;
  for (std::uint32_t i = 0; i < count; ++i) out.push_back(reader.string(kMostFieldBytes));
  return out;
}

AppPasswordInfo info_of(const std::string& key, const AppPasswords::Record& record) {
  return AppPasswordInfo{key.substr(key.find('/') + 1), record.name, record.scopes, record.networks, record.created};
}

// Lower case in groups of four, joined by dashes, as the password is shown.
std::string shown(std::string_view characters) {
  std::string out;
  for (std::size_t i = 0; i < characters.size(); ++i) {
    if (i > 0 && i % 4 == 0) out.push_back('-');
    const char c = characters[i];
    out.push_back(c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c);
  }
  return out;
}

}  // namespace

AppPasswords::AppPasswords(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
                           std::shared_ptr<audit::AuditLog> audit, Executor hashing, crypto::Argon2Costs params)
    : _calls(std::move(store)), _wall(wall), _directory(std::move(directory)), _audit(std::move(audit)), _hashing(std::move(hashing)), _params(params) {}

std::optional<Secret> AppPasswords::normal(std::string_view typed) {
  if (typed.size() > 2 * kCharacters) return std::nullopt;
  SecureBuffer out;
  for (const char c : typed) {
    if (c == '-' || c == ' ') continue;
    const char upper = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
    if (!((upper >= 'A' && upper <= 'Z') || (upper >= '2' && upper <= '7'))) return std::nullopt;
    out.push_back(static_cast<unsigned char>(upper));
  }
  if (out.size() != kCharacters) return std::nullopt;
  return Secret(std::move(out));
}

SecureBuffer AppPasswords::encode(const Record& record) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.string(record.name);
  writer.string(record.selector);
  write_password_hash(writer, record.hash);
  write_strings(writer, record.scopes);
  write_strings(writer, record.networks);
  writer.u64(record.created);
  return writer.take();
}

std::optional<AppPasswords::Record> AppPasswords::decode(std::span<const unsigned char> value) {
  return decode_whole<Record>(value, [](dannan::net::Reader& reader) -> std::optional<Record> {
    if (reader.u8() != kFormat) return std::nullopt;
    Record record;
    record.name = reader.string(kMostFieldBytes);
    record.selector = reader.string(kSelectorCharacters);
    if (record.selector.size() != kSelectorCharacters) return std::nullopt;
    auto hash = read_password_hash(reader);
    if (!hash) return std::nullopt;
    record.hash = std::move(*hash);
    record.scopes = read_strings(reader, kMostScopes);
    record.networks = read_strings(reader, kMostNetworks);
    record.created = reader.u64();
    return record;
  });
}

void AppPasswords::_records(std::string user_id, Executor executor, Done<Outcome<std::vector<Stored>>> done) const {
  using Answer = Outcome<std::vector<Stored>>;
  _calls.list_settled(kTable, std::move(executor), [prefix = user_id + "/", done = std::move(done)](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return done(Answer::from(records));
    std::vector<Stored> out;
    for (const auto& record : records.value) {
      if (record.key.rfind(prefix, 0) != 0) continue;
      auto decoded = decode(record.value);
      if (!decoded) return done(Answer::failure(Fault::failed, "the app password " + record.key + " does not decode"));
      out.push_back(Stored{record.key, std::move(*decoded)});
    }
    std::sort(out.begin(), out.end(),
              [](const Stored& a, const Stored& b) { return a.record.created < b.record.created || (a.record.created == b.record.created && a.key < b.key); });
    done(Answer::success(std::move(out)));
  });
}

void AppPasswords::_record(audit::Event event, Executor executor, std::function<void()> then) const {
  // A failure is logged by the audit log itself; the change has been made.
  _audit->record(std::move(event), kStepDeadline, std::move(executor), [then = std::move(then)](Status) { then(); });
}

void AppPasswords::create(audit::Actor actor, std::string user_id, std::string name, std::vector<std::string> scopes, std::vector<std::string> networks,
                          Deadline deadline, Executor executor, Done<Outcome<Made>> done) {
  using Answer = Outcome<Made>;
  auto answer = answering<Made>(deadline, executor, std::move(done), kChangeLate);
  if (name.empty() || !directory::printable(name, 64)) return answer->finish(Answer::failure(Fault::invalid, "name is printable UTF-8, 1 to 64 bytes"));
  if (scopes.empty()) scopes = {scopes::kDirectoryRead};
  if (scopes.size() > kMostScopes) return answer->finish(Answer::failure(Fault::invalid, "an app password carries at most 32 scopes"));
  for (const auto& scope : scopes) {
    if (const auto kind = scopes::grantable(scope); !kind.ok()) return answer->finish(Answer::from(kind));
  }
  scopes = scopes::united(std::move(scopes));
  if (networks.size() > kMostNetworks) return answer->finish(Answer::failure(Fault::invalid, "an app password names at most 16 networks"));
  for (auto& text : networks) {
    const auto network = network::prefix_of(text);
    if (!network) return answer->finish(Answer::failure(Fault::invalid, "not a network: " + text));
    text = network->to_string();
  }

  auto self = shared_from_this();
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer->finish(Answer::from(user));
    if (!user.value) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    if (user.value->disabled) return answer->finish(Answer::failure(Fault::refused, "the user is disabled"));
    self->_records(user_id, executor, [=](Outcome<std::vector<Stored>> held) {
      if (!held.ok()) return answer->finish(Answer::from(held));
      if (held.value.size() >= kMostPerUser) return answer->finish(Answer::failure(Fault::refused, "a user has at most 32 app passwords"));

      const auto raw = secure_random(kPasswordBytes);
      auto characters = std::make_shared<std::string>(encoding::base32(raw));
      characters->resize(kCharacters);
      const auto instance = dannan::identity::hex(dannan::identity::random_bytes(kInstanceBytes));
      on_pool(
          self->_hashing, [characters, params = self->_params] { return hash_password(byte_span(*characters), params); }, executor,
          [=](Result<PasswordHash> hashed) {
            if (!hashed.ok) return answer->finish(Answer::failure(Fault::failed, hashed.error));
            Record record{name, characters->substr(0, kSelectorCharacters), std::move(hashed.value), scopes, networks, self->_wall.unix_ms() / 1000};
            const auto key = user_id + "/" + instance;
            self->_calls.put_settled(kTable, key, encode(record), 0, executor, [=](store::Write written) {
              if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
              auto made = std::make_shared<Made>(Made{info_of(key, record), text_secret(shown(*characters))});
              self->_record(audit::Event{"app_password.create", actor.id, user_id, actor.source, name + ": " + scopes::join(scopes)}, executor,
                            [answer, made] { answer->finish(Answer::success(Made{made->info, Secret(made->password.reveal())})); });
            });
          });
    });
  });
}

void AppPasswords::list(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<AppPasswordInfo>>> done) const {
  using Answer = Outcome<std::vector<AppPasswordInfo>>;
  auto answer = answering<std::vector<AppPasswordInfo>>(deadline, executor, std::move(done), kReadLate);
  _records(std::move(user_id), executor, [answer](Outcome<std::vector<Stored>> held) {
    if (!held.ok()) return answer->finish(Answer::from(held));
    std::vector<AppPasswordInfo> out;
    for (const auto& one : held.value) out.push_back(info_of(one.key, one.record));
    answer->finish(Answer::success(std::move(out)));
  });
}

void AppPasswords::revoke(audit::Actor actor, std::string user_id, std::string id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  if (id.empty() || id.find('/') != std::string::npos) return answer->finish(Answer::failure(Fault::not_found, "no such app password"));
  auto self = shared_from_this();
  const auto key = user_id + "/" + id;
  _calls.remove_settled(kTable, key, std::nullopt, executor, [=](store::Write written) {
    if (!written.ok()) {
      if (written.error == store::StoreError::not_found || written.error == store::StoreError::removed)
        return answer->finish(Answer::failure(Fault::not_found, "no such app password"));
      return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
    }
    self->_record(audit::Event{"app_password.revoke", actor.id, user_id, actor.source, id}, executor, [answer] { answer->finish(Answer::success()); });
  });
}

void AppPasswords::verify(std::string user_id, Secret password, std::string source, Deadline deadline, Executor executor,
                          Done<Outcome<AppPasswordMatch>> done) {
  using Answer = Outcome<AppPasswordMatch>;
  auto answer = answering<AppPasswordMatch>(deadline, executor, std::move(done), kReadLate);
  auto typed = std::make_shared<std::optional<Secret>>(normal(secret_text(password)));
  auto self = shared_from_this();
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
    if (!user.ok()) return answer->finish(Answer::from(user));
    const bool usable = user.value && !user.value->disabled && user.value->enrolled;
    self->_records(user_id, executor, [=](Outcome<std::vector<Stored>> held) {
      if (!held.ok()) return answer->finish(Answer::from(held));
      boost::system::error_code ec;
      const auto address = network::unmapped(boost::asio::ip::make_address(source, ec));

      // Every record's selector compared, whichever matches; then one hash, of the match or of
      // a stand-in, so the time taken says nothing about which.
      std::optional<Stored> candidate;
      for (const auto& one : held.value) {
        const bool same = *typed && dannan::identity::constant_time_equal((*typed)->reveal().first(kSelectorCharacters), byte_span(one.record.selector));
        if (same) candidate = one;
      }
      const auto from_allowed = [&](const Record& record) {
        if (record.networks.empty()) return true;
        if (ec) return false;
        return std::any_of(record.networks.begin(), record.networks.end(), [&](const std::string& text) {
          const auto network = network::prefix_of(text);
          return network && network->contains(address);
        });
      };
      const bool eligible = usable && candidate && from_allowed(candidate->record);
      const auto hash = candidate ? candidate->record.hash : PasswordHash{self->_params, Bytes(kPasswordSaltBytes, 0), SecureBuffer(kPasswordHashBytes, 0)};
      on_pool(
          self->_hashing,
          [typed, hash] {
            if (!*typed) return false;
            return verify_password((**typed).reveal(), hash);
          },
          executor,
          [=](bool right) {
            if (!right || !eligible) return answer->finish(Answer::failure(Fault::refused, kWrong));
            answer->finish(Answer::success(AppPasswordMatch{user_id, info_of(candidate->key, candidate->record)}));
          });
    });
  });
}

void AppPasswords::forget(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Status> done) {
  auto answer =
      Completion<Status>::start(deadline, executor, std::move(done), [] { return Status::failure("the app passwords were not removed within the deadline"); });
  auto self = shared_from_this();
  _records(user_id, executor, [=](Outcome<std::vector<Stored>> held) {
    if (!held.ok()) return answer->finish(Status::failure(held.message));
    auto keys = std::make_shared<std::vector<std::string>>();
    for (const auto& one : held.value) keys->push_back(one.key);
    auto failed = std::make_shared<bool>(false);
    in_turn<std::string>(
        keys, 0,
        [=](const std::string& key, std::function<void()> next) {
          self->_calls.remove_settled(kTable, key, std::nullopt, executor, [=](store::Write written) {
            if (!written.ok() && written.error != store::StoreError::not_found) *failed = true;
            next();
          });
        },
        [=] {
          if (*failed) return answer->finish(Status::failure("an app password of " + user_id + " could not be removed"));
          if (keys->empty()) return answer->finish(Status::success());
          self->_record(audit::Event{"app_password.forget", actor.id, user_id, actor.source, std::to_string(keys->size()) + " removed"}, executor,
                        [answer] { answer->finish(Status::success()); });
        });
  });
}

}  // namespace lugh::authn
