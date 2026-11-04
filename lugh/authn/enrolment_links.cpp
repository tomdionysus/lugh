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
#include "lugh/core/steps.h"

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr const char* kPrefix = "enrol/";
const std::string kFirstSignIn = "first-sign-in/";

}  // namespace

EnrolmentLinks::EnrolmentLinks(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
                               std::shared_ptr<audit::AuditLog> audit, std::chrono::seconds lifetime)
    : _calls(std::move(store)), _wall(wall), _directory(std::move(directory)), _audit(std::move(audit)), _lifetime(lifetime) {}

namespace {

constexpr const char* kChangeLate = "the enrolment links did not answer within the deadline; the change may yet be made";
constexpr const char* kReadLate = "the enrolment links were not read within the deadline";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

}  // namespace

void EnrolmentLinks::issue(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<Secret>> done) {
  using Answer = Outcome<Secret>;
  auto answer = answering<Secret>(deadline, executor, std::move(done), kChangeLate);
  auto self = shared_from_this();
  _directory->user(user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> read) {
    if (!read.ok()) return answer->finish(Answer::from(read));
    const auto& user = read.value;
    if (!user) return answer->finish(Answer::failure(Fault::not_found, "no such user"));
    if (user->kind != directory::Kind::person) return answer->finish(Answer::failure(Fault::refused, "a service does not enrol"));
    if (user->disabled) return answer->finish(Answer::failure(Fault::refused, "the user is disabled"));
    if (user->enrolled) return answer->finish(Answer::failure(Fault::refused, "the user is enrolled; reset their factors first"));

    self->_calls.list_settled(kTable, executor, [=](Outcome<std::vector<store::Record>> records) {
      if (!records.ok()) return answer->finish(Answer::from(records));
      // The user's earlier links, ended first.
      auto earlier = std::make_shared<std::vector<store::Record>>();
      for (auto& record : records.value) {
        if (record.key.rfind(kPrefix, 0) != 0) continue;
        const auto link = decode(record.value);
        if (link && link->user_id == user_id) earlier->push_back(std::move(record));
      }
      in_turn<store::Record>(
          earlier, 0,
          [=](const store::Record& record, std::function<void()> next) {
            self->_calls.remove_settled(kTable, record.key, record.version, executor, [next](store::Write) { next(); });
          },
          [=] {
            const auto raw = secure_random(kTokenBytes);
            // Held where every step can reach it: a Secret is not copied.
            auto token = std::make_shared<Secret>(text_secret(encoding::base64url(raw)));
            Link link;
            link.user_id = user_id;
            link.issued = (self->_wall.unix_ms() / 1000);
            link.expires = link.issued + static_cast<std::uint64_t>(self->_lifetime.count());
            self->_calls.put_settled(kTable, *_key(*token), encode(link), 0, executor, [=](store::Write written) {
              if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
              self->_record(audit::Event{"enrolment.issue", actor.id, link.user_id, actor.source, "expires " + std::to_string(link.expires)}, executor,
                            [answer, token] { answer->finish(Answer::success(std::move(*token))); });
            });
          });
    });
  });
}

void EnrolmentLinks::peek(Secret token, Deadline deadline, Executor executor, Done<Outcome<std::string>> done) const {
  using Answer = Outcome<std::string>;
  auto answer = answering<std::string>(deadline, executor, std::move(done), kReadLate);
  const auto key = _key(token);
  if (!key) return answer->finish(Answer::failure(Fault::not_found, "no such link"));
  _live(*key, executor, [answer](Outcome<std::pair<Link, std::uint64_t>> live) {
    if (!live.ok()) return answer->finish(Answer::from(live));
    answer->finish(Answer::success(live.value.first.user_id));
  });
}

void EnrolmentLinks::link(Secret token, Deadline deadline, Executor executor, Done<Outcome<Link>> done) const {
  using Answer = Outcome<Link>;
  auto answer = answering<Link>(deadline, executor, std::move(done), kReadLate);
  const auto key = _key(token);
  if (!key) return answer->finish(Answer::failure(Fault::not_found, "no such link"));
  _live(*key, executor, [answer](Outcome<std::pair<Link, std::uint64_t>> live) {
    if (!live.ok()) return answer->finish(Answer::from(live));
    answer->finish(Answer::success(live.value.first));
  });
}

void EnrolmentLinks::spend(Secret token, audit::Actor actor, Deadline deadline, Executor executor, Done<Outcome<std::string>> done) {
  using Answer = Outcome<std::string>;
  auto answer = answering<std::string>(deadline, executor, std::move(done), kChangeLate);
  const auto key = _key(token);
  if (!key) return answer->finish(Answer::failure(Fault::not_found, "no such link"));
  auto self = shared_from_this();
  _live(*key, executor, [=](Outcome<std::pair<Link, std::uint64_t>> live) {
    if (!live.ok()) return answer->finish(Answer::from(live));
    const auto link = live.value.first;
    self->_calls.remove_settled(kTable, *key, live.value.second, executor, [=](store::Write removed) {
      if (!removed.ok()) {
        if (removed.error == store::StoreError::conflict || removed.error == store::StoreError::removed) {
          return answer->finish(Answer::failure(Fault::not_found, "no such link"));
        }
        return answer->finish(Answer::failure(directory::fault_of(removed.error), removed.message));
      }
      self->_record(audit::Event{"enrolment.redeem", actor.id, link.user_id, actor.source, {}}, executor,
                    [answer, link] { answer->finish(Answer::success(link.user_id)); });
    });
  });
}

void EnrolmentLinks::first_sign_in_allow(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  Link link;
  link.user_id = std::move(user_id);
  link.issued = (_wall.unix_ms() / 1000);
  // Until it is spent.
  link.expires = UINT64_MAX;
  _calls.put_settled(kTable, kFirstSignIn + link.user_id, encode(link), 0, executor,
                     [self = shared_from_this(), answer, actor, link, executor](store::Write written) {
                       if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
                       self->_record(audit::Event{"enrolment.first_sign_in", actor.id, link.user_id, actor.source, {}}, executor,
                                     [answer] { answer->finish(Answer::success()); });
                     });
}

void EnrolmentLinks::first_sign_in_allowed(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<bool>> done) const {
  using Answer = Outcome<bool>;
  auto answer = answering<bool>(deadline, executor, std::move(done), kReadLate);
  _calls.get_settled(kTable, kFirstSignIn + user_id, executor, [answer, user_id](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    const auto link = record.value ? decode(record.value->value) : std::nullopt;
    answer->finish(Answer::success(link && link->user_id == user_id));
  });
}

void EnrolmentLinks::first_sign_in_spend(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  const auto key = kFirstSignIn + user_id;
  _calls.get_settled(kTable, key, executor, [self = shared_from_this(), answer, key, executor](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    if (!record.value) return answer->finish(Answer::success());
    self->_calls.remove_settled(kTable, key, std::nullopt, executor, [answer](store::Write) { answer->finish(Answer::success()); });
  });
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

void EnrolmentLinks::_live(std::string key, Executor executor, Done<Outcome<std::pair<Link, std::uint64_t>>> done) const {
  using Answer = Outcome<std::pair<Link, std::uint64_t>>;
  _calls.get_settled(kTable, std::move(key), std::move(executor),
                     [self = shared_from_this(), done = std::move(done)](Outcome<std::optional<store::Record>> record) {
                       if (!record.ok()) return done(Answer::from(record));
                       auto link = record.value ? decode(record.value->value) : std::nullopt;
                       // An expired link is no different, to its holder, from one that never was.
                       if (!link || (self->_wall.unix_ms() / 1000) >= link->expires) return done(Answer::failure(Fault::not_found, "no such link"));
                       done(Answer::success(std::make_pair(std::move(*link), record.value->version)));
                     });
}

void EnrolmentLinks::_record(audit::Event event, Executor executor, std::function<void()> then) const {
  // A failure is logged by the audit log itself; the change has been made.
  _audit->record(std::move(event), kStepDeadline, std::move(executor), [then = std::move(then)](Status) { then(); });
}

}  // namespace lugh::authn
