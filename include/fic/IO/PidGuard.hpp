#pragma once
#include <string>

class PidGuard {
public:
  explicit PidGuard(const char *path);
  ~PidGuard();

  PidGuard(const PidGuard &) = delete;
  PidGuard &operator=(const PidGuard &) = delete;

private:
  std::string path_;
};
