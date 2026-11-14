//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// Built into lugh_tests under -DLUGH_SANITIZE=thread only.
//
// Asio's any_executor shares a polymorphic executor's target behind a reference count, and
// drops the last reference with a release fetch_sub followed by a standalone acquire fence
// (boost/asio/detail/atomic_count.hpp, ref_count_down). That is correct, but ThreadSanitizer
// does not model standalone fences, so the delete on the last holder's thread is reported as
// racing with the decrement on another (Boost 1.83 on Debian 13, first seen on node-a,
// 2026-11-14). Only that destructor is suppressed; a race in what the target wraps still shows.
extern "C" const char* __tsan_default_suppressions() { return "race:boost::asio::execution::detail::shared_target_executor::~shared_target_executor\n"; }
