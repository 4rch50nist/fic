#pragma once
#include <cstdio>
#include <stdexcept>
#include <sys/file.h>

/// RAII phil.
class FileGuard {
private:
  std::FILE *f = nullptr;

public:
  explicit FileGuard() {}

  ~FileGuard() { unbind(); }

  FileGuard(const FileGuard &) = delete;
  FileGuard &operator=(const FileGuard &) = delete;

  FileGuard(FileGuard &&other) noexcept : f{other.f} { other.f = nullptr; }

  FileGuard &operator=(FileGuard &&other) noexcept {
    if (this != &other) {
      if (f) {
        flock(fileno(f), LOCK_UN);
        fclose(f);
      }
      f = other.f;
      other.f = nullptr;
    }

    return *this;
  }

  std::FILE *get() const { return this->f; }
  bool is_open() const { return f != nullptr; }

  /// Bind the path to the file guard. This essentially checks if the file is
  /// already open. If so it will just return false and this must be handled by
  /// the caller. In all other cases, it just opens the file with "rb".
  ///
  /// If it cannot open it then it throws a runtime error.
  /// If it cannot acquire a file lock, it throws a runtime error.
  bool bind(const char *path) {

    /// if f is already bound, then we should ideally let the caller
    /// know that it is bound. So it needs to unbind it first and
    /// them go ahead.
    if (f)
      return false;

    f = std::fopen(path, "rb");
    if (!f)
      throw std::runtime_error("Could not open path provided");

    if (flock(fileno(f), LOCK_SH) != 0) {
      std::fclose(f);
      f = nullptr;
      throw std::runtime_error("Could not lock the file");
    }

    return true;
  }

  /// Unbinds the file by first unlocking the resource and then closing it.
  void unbind() {
    if (f) {
      flock(fileno(f), LOCK_UN);
      fclose(f);
      f = nullptr;
    }
  }
};
