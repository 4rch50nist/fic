#pragma once
#include <cstdio>

class FileGuard {
    std::FILE *f = nullptr;
public:
    explicit FileGuard();
    ~FileGuard();

    FileGuard(const FileGuard &) = delete;
    FileGuard &operator=(const FileGuard &) = delete;

    FileGuard(FileGuard &&other) noexcept;
    FileGuard &operator=(FileGuard &&other) noexcept;
    [[nodiscard]] std::FILE *get() const;
    [[nodiscard]] bool is_open() const;
    bool bind(const char *);
    void unbind();
};