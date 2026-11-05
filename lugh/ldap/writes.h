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

#include "lugh/authn/authenticator.h"
#include "lugh/authn/passwords.h"
#include "lugh/directory/directory.h"
#include "lugh/ldap/authz.h"
#include "lugh/ldap/messages.h"
#include "lugh/ldap/tree.h"
#include "lugh/session/sessions.h"

namespace lugh::ldap {

// The writes (TODO/2026-11-04-ldap.md, "Operations"), each one or a few calls on the directory as
// /api/v1 makes them, so the rules, the versions and the audit are the same: the actor is the bound
// user and the source ldap:<address>. They need lugh:directory.write; a caller who may not even see
// the entry finds it is not there. Made with std::make_shared.
class Writes : public std::enable_shared_from_this<Writes> {
 public:
  // Who is asking, from where, and the Assertion control's filter if the request had one
  // (RFC 4528). `(lughEntryVersion=<n>)` also makes the write conditional on that version, as
  // If-Match does.
  struct Asking {
    Bound bound;
    std::string address;
    std::optional<Filter> assertion;
  };

  Writes(std::shared_ptr<Tree> tree, std::shared_ptr<directory::Directory> directory, std::shared_ptr<session::Sessions> sessions,
         std::shared_ptr<authn::Passwords> passwords, std::shared_ptr<authn::Authenticator> authenticator);

  void add(Asking asking, AddRequest request, Executor executor, Done<Result> done);
  void modify(Asking asking, ModifyRequest request, Executor executor, Done<Result> done);
  void remove(Asking asking, DeleteRequest request, Executor executor, Done<Result> done);
  void rename(Asking asking, ModifyDnRequest request, Executor executor, Done<Result> done);

  // RFC 3062, for the bound user's own password, only when the bind was the main password, with the
  // old one given and through the sign-in's back-off. Every session of theirs ends.
  void password_modify(Asking asking, PasswordModify request, Executor executor, Done<Result> done);

 private:
  struct Target;
  using Checked = std::function<void(Target, std::optional<std::uint64_t>)>;

  // The entry a write names, once the caller is allowed and any assertion holds.
  void _checked(const Asking& asking, const std::string& dn, Executor executor, std::shared_ptr<Completion<Result>> answer, Checked then);
  void _with_assertion(const Asking& asking, Dn dn, Target target, Executor executor, std::shared_ptr<Completion<Result>> answer, Checked then);
  void _modify_user(const Asking& asking, const directory::User& user, std::optional<std::uint64_t> expected, const ModifyRequest& request, Executor executor,
                    std::shared_ptr<Completion<Result>> answer);
  void _modify_group(const Asking& asking, const directory::Group& group, std::optional<std::uint64_t> expected, const ModifyRequest& request,
                     Executor executor, std::shared_ptr<Completion<Result>> answer);
  void _modify_members(const Asking& asking, const directory::Group& group, const ModifyRequest& request, Executor executor,
                       std::shared_ptr<Completion<Result>> answer);
  // Each DN's user ID, in order; no_such_object for the first that is nobody.
  void _members_of(std::vector<std::string> dns, Executor executor, std::function<void(std::optional<std::vector<std::string>>)> then) const;

  std::shared_ptr<Tree> _tree;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<session::Sessions> _sessions;
  std::shared_ptr<authn::Passwords> _passwords;
  std::shared_ptr<authn::Authenticator> _authenticator;
};

}  // namespace lugh::ldap
