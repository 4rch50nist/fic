#include "SignerClient.hpp"
#include "fic/Key/KeyFactory.hpp"
#include <cstring>
#include <sodium.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void send_all(int sock, const uint8_t *data, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t sent = write(sock, data + total, len - total);
    if (sent <= 0)
      throw std::runtime_error("socket write failed");
    total += static_cast<size_t>(sent);
  }
}

static void recv_all(int sock, uint8_t *data, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t recvd = read(sock, data + total, len - total);
    if (recvd <= 0)
      throw std::runtime_error("socket read failed");
    total += static_cast<size_t>(recvd);
  }
}

std::array<uint8_t, 64>
request_signature_from_host(const std::vector<uint8_t> &message,
                            const std::string &socket_path) {
  int sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    throw std::runtime_error("failed to create socket");

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
  socklen_t len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) +
                                         strlen(addr.sun_path));

  if (connect(sock, (sockaddr *)&addr, len) < 0) {
    close(sock);
    std::string("connect failed: ") + std::strerror(errno);
  }

  len = static_cast<socklen_t>(message.size());
  send_all(sock, reinterpret_cast<uint8_t *>(&len), sizeof(len));

  send_all(sock, message.data(), message.size());

  std::array<uint8_t, 64> sig{};
  recv_all(sock, sig.data(), sig.size());

  close(sock);
  return sig;
}

bool verify_signature(const std::vector<uint8_t> &msg,
                      const std::array<uint8_t, 64> &sig) {

  std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk;
  if (KeyFactory::create_key_provider()->load_public_key(pk)) {
    return false;
  }

  return crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(),
                                     pk.data()) == 0;
}
