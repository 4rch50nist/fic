#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <sodium.h>

void cleanup();
void signal_handler(int);

class SignerServer {
public:
  explicit SignerServer(const char *socket_path, const char *ipc_path)
      : socket_path_{socket_path}, ipc_path_{ipc_path} {
    server_fd_ = make_unix_server(socket_path_);
    ipc_fd_ = make_unix_server(ipc_path_);

    if (server_fd_ < 0 || ipc_fd_ < 0) {
      cleanup();
      throw std::runtime_error("failed to create socket");
    }

    load_keys();
  }

  ~SignerServer() { cleanup(); }

  SignerServer(const SignerServer &) = delete;

  SignerServer &operator=(const SignerServer &) = delete;

  void run();
  void stop() { running_ = false; }
  void refresh_keys() { load_keys(); }

private:
  void load_keys();

  void handle_signing_client(int);
  void handle_ipc_client(int);
  int make_unix_server(const char *);
  void cleanup();

  const char *socket_path_;
  const char *ipc_path_;

  int server_fd_ = -1;
  int ipc_fd_ = -1;

  std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk_{};
  std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk_{};

  std::atomic_bool running_{false};
};
