//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "lugh/core/completion.h"
#include "lugh/directory/directory.h"
#include "lugh/ldap/dn.h"
#include "lugh/ldap/filter.h"
#include "lugh/ldap/messages.h"

namespace lugh::ldap {

// Where a DN falls in the tree.
struct Place {
  enum class Kind { outside, base, people, services, groups, person, service, group };
  Kind kind = Kind::outside;
  // A leaf's name, folded.
  std::string name;

  bool leaf() const { return kind == Kind::person || kind == Kind::service || kind == Kind::group; }
};

// What a walk of the tree found.
struct Listed {
  ResultCode code = ResultCode::success;
  std::string message;
  std::vector<Entry> entries;
  // Where a next page starts; empty when this is the last.
  std::string next;
};

// The tree (TODO/2026-11-04-ldap.md, "The tree"): fixed, generated from the directory, with nothing
// stored as an LDAP entry. Every mapping from a user or a group to a DN or to attributes is here, so
// a change of layout touches this file. Made with std::make_shared.
class Tree : public std::enable_shared_from_this<Tree> {
 public:
  struct Settings {
    std::string base_dn;
    // {name} is the user's. Neither is stored.
    std::string home = "/home/{name}";
    std::string shell = "/bin/bash";
    // The group every numbered user has as their primary; none, no posixAccount.
    std::string primary_group;
  };

  // Whether a caller may see this entry.
  using Visible = std::function<bool(const Entry&)>;

  struct Walk {
    Dn base;
    Scope scope = Scope::base;
    Filter filter;
    Visible visible;
    // The most entries to answer, and the page token to go on from, if any.
    std::size_t most = 0;
    std::string after;
  };

  // `settings.base_dn` must parse, and name something: what could not happen throws.
  Tree(std::shared_ptr<directory::Directory> directory, Settings settings);

  const Dn& base() const { return _base; }
  std::string base_text() const { return to_string(_base); }

  Place locate(const Dn& dn) const;

  // A user's DN, by their kind, and a group's.
  std::string dn_of(const directory::User& user) const;
  std::string dn_of(const directory::Group& group) const;

  // Each entry `walk` covers that its filter matches and `visible` allows, in a fixed order, at most
  // `most`. no_such_object for a base that is not in the tree, or that the caller may not see. A
  // filter that pins one entry opens that one record; only a general filter reads them all.
  void walk(Walk walk, Deadline deadline, Executor executor, Done<Listed> done) const;

 private:
  struct Loaded;
  void _answer(std::shared_ptr<const Walk> walk, const Place& place, const Loaded& loaded, const std::shared_ptr<Completion<Listed>>& answer) const;
  void _load_all(std::shared_ptr<const Walk> walk, Place place, Executor executor, std::shared_ptr<Completion<Listed>> answer) const;
  void _load_user(std::shared_ptr<const Walk> walk, Place place, std::optional<directory::User> user, Executor executor,
                  std::shared_ptr<Completion<Listed>> answer) const;
  void _load_group(std::shared_ptr<const Walk> walk, Place place, std::optional<directory::Group> group, Executor executor,
                   std::shared_ptr<Completion<Listed>> answer) const;

  Entry _container(Place::Kind kind) const;
  Entry _person(const directory::User& user, const std::vector<const directory::Group*>& groups, std::optional<std::uint32_t> primary_gid) const;
  Entry _group(const directory::Group& group, const std::vector<const directory::User*>& members) const;

  std::shared_ptr<directory::Directory> _directory;
  Settings _settings;
  Dn _base;
  Dn _normal_base;
};

}  // namespace lugh::ldap
