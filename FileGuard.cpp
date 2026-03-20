#include <cstdio>
#include <sys/file.h>

class FileGuard {
private:
  std::FILE *f;

public:
  explicit FileGuard(std::FILE *f) : f{f} {}

  ~FileGuard() {
    if (f) {
      flock(fileno(f), LOCK_UN);
      fclose(f);
    }
  }

  FileGuard(const FileGuard &) = delete;
  FileGuard &operator=(const FileGuard &) = delete;

  FileGuard(FileGuard &&other) noexcept : f{other.f} { other.f = nullptr; }

  FileGuard &operator=(FileGuard &&other) noexcept {
    if (this != &other) {
      if (f)
        flock(fileno(f), LOCK_UN);
      f = other.f;
      other.f = nullptr;
    }

    return *this;
  }

  const std::FILE *get() const { return this->f; }
};
