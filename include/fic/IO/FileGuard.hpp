#pragma once
#include <cstdio>

/**
 * @brief RAII wrapper around a C FILE handle.
 *
 * Ensures the underlying file is closed exactly once regardless of how
 * control leaves the owning scope — normal return, exception, or early exit.
 * Moveable but non-copyable; at most one FileGuard owns a given handle at
 * any time.
 *
 * Typical usage:
 * @code
 *   FileGuard fg;
 *   fg.bind("/path/to/file");   // opens the file
 *   std::fread(..., fg.get());  // use the raw handle
 *   // destructor closes the file automatically
 * @endcode
 */
class FileGuard {
  std::FILE *f = nullptr;

public:
  /**
   * @brief Construct an unbound FileGuard holding no file handle.
   *
   * Call bind() before using get() or is_open().
   */
  explicit FileGuard();

  /**
   * @brief Close the managed file handle, if any.
   *
   * Equivalent to calling unbind(). Safe to call on an unbound guard.
   */
  ~FileGuard();

  FileGuard(const FileGuard &) = delete;
  FileGuard &operator=(const FileGuard &) = delete;

  /**
   * @brief Transfer ownership of the file handle from @p other.
   *
   * @p other is left unbound after the move.
   */
  FileGuard(FileGuard &&other) noexcept;

  /**
   * @brief Close any currently held handle, then take ownership from @p other.
   *
   * @p other is left unbound after the move. Self-assignment is safe.
   */
  FileGuard &operator=(FileGuard &&other) noexcept;

  /**
   * @brief Return the raw FILE pointer.
   *
   * @return The managed handle, or nullptr if unbound.
   * @note Do not call fclose() on the returned pointer — the guard owns it.
   */
  [[nodiscard]] std::FILE *get() const;

  /**
   * @brief Check whether a file handle is currently held.
   *
   * @return true if bound to an open file, false otherwise.
   */
  [[nodiscard]] bool is_open() const;

  /**
   * @brief Open the file at @p path in binary read mode and take ownership.
   *
   * If the guard is already bound, the existing handle is closed before
   * opening the new file.
   *
   * @param path  Null-terminated path to the file to open.
   * @return      true on success, false if the file could not be opened.
   * @throws std::runtime_error if the file cannot be opened.
   */
  bool bind(const char *path);

  /**
   * @brief Close the managed file handle and reset to the unbound state.
   *
   * No-op if the guard is already unbound.
   */
  void unbind();
};
