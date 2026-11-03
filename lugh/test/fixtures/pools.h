//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/thread_pool.hpp>

#include "core/task.h"

// The pools the service suspends on, for tests: one shared pool of real threads, so work
// handed to it runs elsewhere and comes back, as in the service.
inline lugh::Executor test_pool() {
  static boost::asio::thread_pool pool(2);
  return pool.get_executor();
}
