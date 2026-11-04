//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// Built into lugh_tests under -DLUGH_SANITIZE=address only.
//
// GoogleTest comes from MacPorts, built without ASan, and its std::vector code meets the
// same inline code compiled here with libc++'s container annotations. Where the two copies
// mix, ASan reports a container overflow that is not one: it fires while GoogleTest
// registers the tests, before any of Lugh runs. Container-overflow detection is therefore
// off in the test binary; every heap, stack and use-after-free check stays on.
extern "C" const char* __asan_default_options() { return "detect_container_overflow=0"; }
