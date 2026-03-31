#include "FileGuard.hpp"

#include <cstdio>
#include <stdexcept>
#include <sys/file.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

FileGuard::FileGuard() = default;

FileGuard::~FileGuard(){
    unbind();
}
FileGuard::FileGuard(FileGuard &&other)noexcept : f{other.f}{
    other.f = nullptr;
}

FileGuard& FileGuard::operator=(FileGuard&& other) noexcept {
    if (this != &other) {
        unbind();
        f = other.f;
        other.f = nullptr;
    }
    return *this;
}

std::FILE * FileGuard::get() const { return this->f; }
bool FileGuard::is_open() const { return f != nullptr; }

bool FileGuard::bind(const char *path) {
    if (f)
        return false;

    f = std::fopen(path, "rb");
    if (!f)
        throw std::runtime_error("Could not open path provided");

#ifdef _WIN32
    HANDLE h = (HANDLE)_get_osfhandle(fileno(f));
    OVERLAPPED ov = {};

    if (!LockFileEx(h, 0, 0, MAXDWORD, MAXDWORD, &ov)) {
        std::fclose(f);
        f = nullptr;
        throw std::runtime_error("Could not lock the file");
    }
#else
    if (flock(fileno(f), LOCK_SH) != 0) {
        std::fclose(f);
        f = nullptr;
        throw std::runtime_error("Could not lock the file");
    }
#endif

    return true;
}

void FileGuard::unbind() {
    if (f) {
#ifdef _WIN32
        HANDLE h = (HANDLE)_get_osfhandle(fileno(f));
        OVERLAPPED ov = {};
        UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov);
#else
        flock(fileno(f), LOCK_UN);
#endif
        fclose(f);
        f = nullptr;
    }
}
