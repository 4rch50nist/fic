#include "include/fic/IO/PidGuard.hpp"
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <unistd.h>

PidGuard::PidGuard(const char *path) : path_(path) {
  // check if a pid file already exists
  std::ifstream existing(path_);
  if (existing.is_open()) {
    pid_t pid = 0;
    existing >> pid;
    existing.close();

    if (pid > 0) {
      // kill(pid, 0) — no signal sent, just checks if process exists
      if (kill(pid, 0) == 0) {
        throw std::runtime_error("signer already running with PID " +
                                 std::to_string(pid));
      }
    }
  }

  // write our PID
  std::ofstream out(path_);
  if (!out.is_open())
    throw std::runtime_error("could not write PID file: " + path_);

  out << getpid() << "\n";
}

PidGuard::~PidGuard() { std::remove(path_.c_str()); }
