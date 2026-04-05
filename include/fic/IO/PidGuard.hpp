#pragma once
#include <string>

/**
 * @brief RAII guard that ensures at most one instance of a process is running.
 *
 * On construction, writes the current process PID to a file at the given
 * path. If the file already exists and its recorded PID corresponds to a
 * live process, construction fails with an exception — preventing a second
 * instance from starting. On destruction, the PID file is removed.
 *
 * Stale PID files left by a previous crash are detected via kill(pid, 0)
 * and silently overwritten.
 *
 * Typical usage:
 * @code
 *   int main() {
 *       PidGuard guard("/tmp/fic_signer.pid"); // throws if already running
 *       // ... rest of main
 *   } // PID file removed automatically on exit
 * @endcode
 *
 * @note Non-copyable and non-moveable — exactly one guard should exist for
 *       the lifetime of the process.
 */
class PidGuard {
public:
  /**
   * @brief Acquire the single-instance lock by writing the current PID to
   *        @p path.
   *
   * If a PID file already exists at @p path and the recorded process is
   * still alive, throws to prevent a second instance from running. If the
   * recorded process is no longer alive (stale file), the file is
   * overwritten with the current PID.
   *
   * @param path  Null-terminated path at which to create the PID file.
   * @throws std::runtime_error if another instance is already running, or
   *         if the PID file cannot be written.
   */
  explicit PidGuard(const char *path);

  /**
   * @brief Release the lock by removing the PID file.
   *
   * Safe to call even if construction partially failed. No-op if the
   * file has already been removed.
   */
  ~PidGuard();

  PidGuard(const PidGuard &) = delete;
  PidGuard &operator=(const PidGuard &) = delete;

private:
  std::string
      path_; ///< Path of the PID file, retained for removal on destruction.
};
