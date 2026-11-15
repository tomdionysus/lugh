//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/contract/time_source.h"
#include "dannan/status/log.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/backoff.h"
#include "lugh/authn/enrolment_links.h"
#include "lugh/authn/factors.h"
#include "lugh/authn/passwords.h"
#include "lugh/authn/policy.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/task.h"
#include "lugh/directory/directory.h"

namespace lugh::authn {

// One person part way through signing in, held by the caller between steps (P6 keeps it
// server side, behind the pre-session cookie). It says who and how far, never a secret.
// Each step takes it by value and answers the next, so no step holds the caller's copy
// across a suspension.
struct SignIn {
  enum class Stage {
    // The password was right; a TOTP or recovery code is next.
    second_factor,
    // Came in by an enrolment link and set a password; a TOTP factor is next, and nothing
    // else is open to them until it is confirmed.
    enrolment,
    // Signed in, at `reached`.
    complete,
    // Over: too many wrong codes, or too long. Start again from the password.
    ended,
  };

  std::string user_id;
  Stage stage = Stage::ended;
  Assurance required = Assurance::mfa;
  Assurance reached = Assurance::pwd;
  // RFC 8176's values, in the order used: "pwd", "otp", and for WebAuthn "hwk" (a key bound to
  // its device) or "swk" (a synced passkey), with "user" when the authenticator verified them.
  std::vector<std::string> amr;
  std::uint32_t wrong_codes = 0;
  std::chrono::steady_clock::time_point started{};
};

// What a step answered.
struct Step {
  enum class Kind {
    // Not signed in, and not told why: an unknown name, a wrong password, a disabled
    // account and a person who is not enrolled all look the same.
    refused,
    // Too many failures from this account or address: try again after `retry_after`.
    wait,
    // The sign-in is over; start again.
    ended,
    // Moved on: SignIn::stage says to what.
    next,
    // The store or the randomness failed.
    failed,
  };

  Kind kind = Kind::refused;
  std::chrono::seconds retry_after{0};
  // After a recovery code: how many are left, for the user to be told.
  std::optional<std::size_t> recovery_left;
  // At the end of enrolment: the recovery codes, shown once.
  std::vector<Secret> recovery_codes;
  // The sign-in as this step left it, for the caller to keep.
  SignIn sign_in;

  static Step of(Kind kind, SignIn sign_in = {}) {
    Step step;
    step.kind = kind;
    step.sign_in = std::move(sign_in);
    return step;
  }
};

// Signing in: a password, then a second factor, as the user's policy requires; or, from an
// enrolment link, a new password, then a second factor enrolled. Every step is audited, and
// failures back off per account and per source address. Every step takes Dannan's shape
// (core/completion.h): the hashing runs on the hashing pool and the records on the store,
// and the caller is answered on its own executor, `failed` when a read could not happen or
// the deadline passed. Made with std::make_shared.
class Authenticator : public std::enable_shared_from_this<Authenticator> {
 public:
  struct Settings {
    Backoff::Rules account{};
    // An address may be a whole office behind one NAT, so it gets more room.
    Backoff::Rules address{20, std::chrono::seconds(1), std::chrono::minutes(15), std::chrono::hours(1)};
    // Wrong codes in one sign-in before it ends.
    std::uint32_t most_wrong_codes = 5;
    // How long a sign-in may take, from the password to the last step.
    std::chrono::seconds lifetime{std::chrono::minutes(15)};
    // What an authenticator app shows the account under.
    std::string issuer = "Lugh";
  };

  Authenticator(std::shared_ptr<dannan::status::LogSink> log, const dannan::contract::TimeSource& time, std::shared_ptr<directory::Directory> directory,
                std::shared_ptr<Passwords> passwords, std::shared_ptr<Factors> factors, std::shared_ptr<Policies> policies,
                std::shared_ptr<EnrolmentLinks> links, std::shared_ptr<audit::AuditLog> audit, Settings settings);

  // A name or an address, and a password. On `next`, the sign-in is at the second factor,
  // at enrolment (root's first), or complete.
  void password(std::string login, Secret password, std::string source, Deadline deadline, Executor executor, Done<Step> done);

  // How long this account or address must still wait, if it must: for a way of signing in that
  // has to honour the same back-off without going through password().
  std::optional<std::chrono::seconds> waiting_for(const std::string& user_id, const std::string& source) const;

  void totp(SignIn sign_in, std::string code, std::string source, Deadline deadline, Executor executor, Done<Step> done);
  void recovery(SignIn sign_in, Secret code, std::string source, Deadline deadline, Executor executor, Done<Step> done);

  // An enrolment link and the password to set. On `next`, the sign-in is at enrolment. The
  // link is spent only once the password has been accepted, so a refused password leaves
  // it working.
  void redeem(Secret token, Secret password, std::string source, Deadline deadline, Executor executor, Done<Step> done);

  // At enrolment: a TOTP secret to show, then a code from it. On `next` the user is
  // enrolled, signed in, and given their recovery codes.
  void enrol_begin(SignIn sign_in, std::string source, Deadline deadline, Executor executor, Done<Outcome<TotpSetup>> done);
  void enrol_confirm(SignIn sign_in, std::string factor_id, std::string code, std::string source, Deadline deadline, Executor executor, Done<Step> done);

  // WebAuthn (TODO/2026-11-15-p11-webauthn.md, W4). `expected` carries the RP ID, the origins
  // and the challenge the caller issued and claimed; the ceremony's parts are as the browser
  // returned them. A refused assertion counts as a wrong code does.
  //
  // At the second factor: an assertion by one of the user's credentials. A password and a
  // WebAuthn credential reach phr (amr pwd and hwk or swk, and user when the authenticator
  // verified them).
  void webauthn(SignIn sign_in, std::string credential_id, webauthn::Expected expected, Bytes client_data_json, Bytes authenticator_data, Bytes signature,
                std::string source, Deadline deadline, Executor executor, Done<Step> done);

  // Passwordless: an assertion by a discoverable credential, for the user its user handle
  // names, with the user verified (required here whatever `expected` says). It signs in alone
  // at phr. An unknown handle, a disabled or service account, a person not enrolled and an
  // assertion that fails all look the same, and back off as a wrong password does.
  void passkey(std::string user_handle, std::string credential_id, webauthn::Expected expected, Bytes client_data_json, Bytes authenticator_data,
               Bytes signature, std::string source, Deadline deadline, Executor executor, Done<Step> done);

  // At enrolment, a WebAuthn credential in place of a TOTP secret. On `next` the user is
  // enrolled, signed in, and given their recovery codes.
  void enrol_webauthn(SignIn sign_in, std::string name, webauthn::Expected expected, Bytes client_data_json, Bytes attestation_object, std::string source,
                      Deadline deadline, Executor executor, Done<Step> done);

  // Removes a factor, refusing the user's last while their policy requires one.
  void remove_factor(audit::Actor actor, std::string user_id, std::string factor_id, Deadline deadline, Executor executor, Done<Outcome<>> done);

  // An administrator's reset for a user who has lost every factor: they all go, and the user
  // must enrol again through a new link. P6 adds revoking every session and token.
  void reset_factors(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done);

 private:
  using Then = std::function<void()>;

  bool _live(SignIn& sign_in, SignIn::Stage stage) const;
  std::optional<std::chrono::seconds> _waiting(const std::string& account, const std::string& address) const;
  void _failed(const std::string& account, const std::string& address);
  void _code_refused(SignIn sign_in, std::string source, std::string action, Executor executor, Done<Step> done);
  void _complete(SignIn sign_in, std::string source, Executor executor, Done<Step> done);
  void _enrolled(SignIn sign_in, std::string source, Executor executor, Done<Step> done);
  void _record(std::string action, std::string actor, std::string subject, std::string source, std::string detail, Executor executor, Then then);

  dannan::status::ScopedLogger _logger;
  const dannan::contract::TimeSource& _time;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<Passwords> _passwords;
  std::shared_ptr<Factors> _factors;
  std::shared_ptr<Policies> _policies;
  std::shared_ptr<EnrolmentLinks> _links;
  std::shared_ptr<audit::AuditLog> _audit_log;
  Settings _settings;
  Backoff _accounts;
  Backoff _addresses;
};

}  // namespace lugh::authn
