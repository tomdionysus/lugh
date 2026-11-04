//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include "lugh/audit/audit_log.h"
#include "lugh/test/fixtures/run.h"

// The audit log's operations, waited for, as the tests call them.
inline constexpr lugh::Deadline kTestDeadline = std::chrono::seconds(30);

inline lugh::Result<std::shared_ptr<lugh::audit::AuditLog>> audit_open(std::shared_ptr<dannan::status::LogSink> log, std::shared_ptr<lugh::store::Store> store,
                                                                       const dannan::contract::WallClock& wall) {
  return wait_for<lugh::Result<std::shared_ptr<lugh::audit::AuditLog>>>(
      [&](lugh::Executor executor, auto done) { lugh::audit::AuditLog::open(log, store, wall, kTestDeadline, executor, done); });
}

inline lugh::Status audit_record(const std::shared_ptr<lugh::audit::AuditLog>& log, lugh::audit::Event event) {
  return wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { log->record(std::move(event), kTestDeadline, executor, done); });
}

// The page, which must have been read.
inline std::vector<lugh::audit::Entry> audit_entries(const std::shared_ptr<lugh::audit::AuditLog>& log, std::uint64_t from, std::size_t most) {
  auto page = wait_for<lugh::Outcome<std::vector<lugh::audit::Entry>>>(
      [&](lugh::Executor executor, auto done) { log->entries(from, most, kTestDeadline, executor, done); });
  EXPECT_TRUE(page.ok()) << page.message;
  return page.value;
}

inline lugh::Result<std::uint64_t> audit_verify(const std::shared_ptr<lugh::audit::AuditLog>& log) {
  return wait_for<lugh::Result<std::uint64_t>>([&](lugh::Executor executor, auto done) { log->verify(kTestDeadline, executor, done); });
}
