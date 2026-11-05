//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "lugh/authn/app_passwords.h"
#include "lugh/authn/authenticator.h"
#include "lugh/core/completion.h"
#include "lugh/core/secret.h"
#include "lugh/directory/directory.h"
#include "lugh/http/caller.h"
#include "lugh/ldap/messages.h"
#include "lugh/ldap/tree.h"
#include "lugh/scopes/grants.h"

namespace lugh::ldap {

// A connection's identity once a bind has succeeded.
struct Bound {
  std::string dn;
  // The same type /api/v1 resolves, so an operation is checked against the API's scopes.
  http::Caller caller;
  // Set when the bind was an app password: which, and the most it may do.
  std::optional<std::string> app_password;
  std::vector<std::string> app_password_scopes;
};

struct BindAnswer {
  Result result;
  std::optional<Bound> bound;
};

// Whether a password checked by the authenticator is all this user needs, since LDAP cannot carry a
// second factor: it completed the sign-in, or stopped at a factor their policy does not ask for.
bool password_alone_enough(const authn::Step& step);

// What a bind proves (TODO/2026-11-04-ldap.md, "What a bind proves"). A main password goes through
// the authenticator, with its back-off, lockout and audit, and passes only if that completes the
// sign-in, since LDAP cannot carry a second factor; an app password is tried first when what was
// presented has the shape of one, and a miss is counted as a wrong password is. Every refusal says
// the same, after the same work. Made with std::make_shared.
class Binder : public std::enable_shared_from_this<Binder> {
 public:
  Binder(std::shared_ptr<Tree> tree, std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Authenticator> authenticator,
         std::shared_ptr<authn::AppPasswords> app_passwords, std::shared_ptr<scopes::Grants> grants, std::shared_ptr<audit::AuditLog> audit);

  // `address` is the client's, as the socket has it.
  void bind(std::string name, Secret password, std::string address, Deadline deadline, Executor executor, Done<BindAnswer> done);

  // The identity as it stands now, for each operation on a connection that may outlive a change:
  // nothing for a user since removed or disabled, or an app password since revoked. Scopes read
  // again, and an app password's cut to its owner's. `failed` when the store is.
  void current(Bound bound, Deadline deadline, Executor executor, Done<Outcome<std::optional<Bound>>> done) const;

 private:
  void _password(std::string name, std::string dn, std::shared_ptr<Secret> password, std::string address, Executor executor,
                 std::shared_ptr<Completion<BindAnswer>> answer);

  std::shared_ptr<Tree> _tree;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<authn::Authenticator> _authenticator;
  std::shared_ptr<authn::AppPasswords> _app_passwords;
  std::shared_ptr<scopes::Grants> _grants;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::ldap
