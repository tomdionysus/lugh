#!/bin/sh
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#
# Builds the Debian package (lugh, and its debug symbols) on Debian trixie from a git checkout,
# natively for the machine's architecture, against the installed Dannan (libdannan-dev). The
# package is written to build-deb/. See docs/packaging.md.
#
#   sudo apt install dpkg-dev && sudo apt build-dep ./
#   tools/build-deb.sh [dpkg-buildpackage options]
#
# The version comes from `git describe`: the tag 0.2.0 gives 0.2.0, and a build three commits
# later 0.2.0+git3.gabc1234, which sorts after 0.2.0 and before 0.2.1; where no tag is reachable
# (develop), the tree's version and the commit, 0.2.0+git.gabc1234. Uncommitted changes add
# .dirty. DEB_BUILD_OPTIONS=nocheck skips the tests, and with them the need for Dagda and Lir.

set -eu

top=$(git rev-parse --show-toplevel)
cd "$top"

project=$(sed -nE '/^project\(lugh/,/\)/s/^ *VERSION ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' CMakeLists.txt)
if [ -z "$project" ]; then
    echo "build-deb.sh: no version in CMakeLists.txt's project()" >&2
    exit 1
fi

# Release tags sit on main's release merges, which develop never merges back: a build where none
# is reachable is the tree's version and the commit.
if describe=$(git describe --tags --match '[0-9]*.[0-9]*.[0-9]*' --dirty 2>/dev/null); then
    version=$(echo "$describe" | sed -E 's/-([0-9]+)-g([0-9a-f]+)/+git\1.g\2/; s/-dirty$/.dirty/')
else
    describe=$(git describe --always --dirty)
    version="$project+git.g$(echo "$describe" | sed -E 's/-dirty$/.dirty/')"
fi
# A build of a tag is a release, and has to be the version the tree says. Between tags the tree
# may already carry the next one.
case "$version" in
    *+git*) ;;
    "$project" | "$project".dirty) ;;
    *)
        echo "build-deb.sh: the tag says $describe and CMakeLists.txt says $project" >&2
        exit 1
        ;;
esac

# One job per CPU unless the caller says otherwise.
case " ${DEB_BUILD_OPTIONS:-} " in
    *" parallel="*) ;;
    *) export DEB_BUILD_OPTIONS="${DEB_BUILD_OPTIONS:+$DEB_BUILD_OPTIONS }parallel=$(nproc)" ;;
esac

cat >debian/changelog <<END
lugh ($version) trixie; urgency=medium

  * Built from $describe.

 -- tomdionysus <tomdionysus@users.noreply.github.com>  $(date -R)
END

dpkg-buildpackage -us -uc -b "$@"

mkdir -p build-deb
for f in ../lugh_"$version"_*.deb ../lugh-dbgsym_"$version"_*.deb ../lugh_"$version"_*.buildinfo ../lugh_"$version"_*.changes; do
    if [ -e "$f" ]; then mv "$f" build-deb/; fi
done
ls -l build-deb/*"$version"*
