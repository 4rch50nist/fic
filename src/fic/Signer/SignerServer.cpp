#include "include/fic/Signer/SignerServer.hpp"
#include "include/fic/Key/KeyFactory.hpp"
#include "include/fic/Signer/SignerClient.hpp"
#include <array>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

void SignerServer::run() {
  running_ = true;
  std::cout << "Signing Server listening on:" << server_fd_ << std::endl;
  std::cout << "IPC listening on:" << ipc_fd_ << std::endl;

  while (running_) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(server_fd_, &rfds);
    FD_SET(ipc_fd_, &rfds);
    int maxfd = std::max(server_fd_, ipc_fd_) + 1;

    timeval tv{1, 0};
    int n = select(maxfd, &rfds, nullptr, nullptr, &tv);
    if (n < 0 && errno != EINTR) {
      perror("select");
      break;
    }
    if (n <= 0)
      continue;

    if (FD_ISSET(ipc_fd_, &rfds)) {
      int conn = accept(ipc_fd_, nullptr, nullptr);
      if (conn >= 0)
        handle_ipc_client(conn);
    }

    if (FD_ISSET(server_fd_, &rfds)) {
      int client = accept(server_fd_, nullptr, nullptr);
      if (client >= 0)
        handle_signing_client(client);
    }
  }
}

void SignerServer::load_keys() {
  sodium_memzero(sk_.data(), sk_.size());
  KeyFactory::create_key_provider()->load_secret_key(sk_);
  crypto_sign_ed25519_sk_to_pk(pk_.data(), sk_.data());
  std::cout << "Keys loaded.\n";
}

void SignerServer::handle_ipc_client(int conn) {
  char buf[32]{};
  read(conn, buf, sizeof(buf) - 1);
  close(conn);

  if (std::strcmp(buf, "keys_changed") == 0) {
    std::cout << "IPC: reloading keys...\n";
    load_keys();
  }
}

void SignerServer::handle_signing_client(int client) {
  try {
    uint32_t len = 0;
    recv_all(client, reinterpret_cast<uint8_t *>(&len), sizeof(len));
    if (len > 10 * 1024 * 1024)
      throw std::runtime_error("message too large");

    std::vector<uint8_t> msg(len);
    recv_all(client, msg.data(), len);

    std::array<uint8_t, crypto_sign_BYTES> sig{};
    crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(),
                         sk_.data());
    send_all(client, sig.data(), sig.size());
  } catch (const std::exception &e) {
    std::cerr << "client error: " << e.what() << "\n";
  }
  close(client);
}

int SignerServer::make_unix_server(const char *path) {
  unlink(path);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    perror("bind");
    close(fd);
    return -1;
  }
  chmod(path, 0600);
  listen(fd, 5);
  return fd;
}

void SignerServer::cleanup() {
  if (server_fd_ >= 0) {
    close(server_fd_);
    server_fd_ = -1;
  }
  if (ipc_fd_ >= 0) {
    close(ipc_fd_);
    ipc_fd_ = -1;
  }
  unlink(socket_path_);
  unlink(ipc_path_);
  sodium_memzero(sk_.data(), sk_.size());
}
