#pragma once

#include <string>
#include <utility>

namespace lugh {

// What a fallible operation answers, in place of an exception across a component boundary.
struct Status {
  bool ok = true;
  std::string error;

  static Status success() { return Status{}; }
  static Status failure(std::string error) { return Status{false, std::move(error)}; }
};

// A Status with the value it produced. value is meaningful only when ok.
template <typename T>
struct Result {
  bool ok = false;
  std::string error;
  T value{};

  static Result success(T value) { return Result{true, {}, std::move(value)}; }
  static Result failure(std::string error) { return Result{false, std::move(error), T{}}; }
};

}  // namespace lugh
