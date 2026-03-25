#include "SignerClient.cpp"
#include "fic/Key/Providers/KeyChainProvider.cpp"
#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

static const char *SOCKET_PATH = "/tmp/fic_file_signer.sock";
static const char *SECRET_KEY_FILE = "secret.key";

static int server_fd = -1;

void cleanup() {
  if (server_fd >= 0)
    close(server_fd);
  unlink(SOCKET_PATH);
}

void signal_handler(int) {
  std::cout << "\nShutting down signer...\n";
  cleanup();
  std::exit(0);
}

std::vector<uint8_t> load_secret_key() {
  FILE *f = fopen(SECRET_KEY_FILE, "rb");
  if (!f)
    throw std::runtime_error("failed to open secret.key");

  std::vector<uint8_t> key(crypto_sign_SECRETKEYBYTES);

  if (fread(key.data(), 1, key.size(), f) != key.size()) {
    fclose(f);
    throw std::runtime_error("failed to read secret key");
  }

  fclose(f);
  return key;
}

int main() {
  if (sodium_init() < 0) {
    std::cerr << "libsodium init failed\n";
    return 1;
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  KeyChainProvider kp{};
  std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk;
  kp.load_secret_key(sk);

  server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server_fd < 0) {
    perror("socket");
    return 1;
  }

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  unlink(SOCKET_PATH); // remove old socket

  if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    cleanup();
    return 1;
  }

  if (listen(server_fd, 5) < 0) {
    perror("listen");
    cleanup();
    return 1;
  }

  std::cout << "Signer listening on " << SOCKET_PATH << "\n";

  while (true) {
    int client = accept(server_fd, nullptr, nullptr);
    if (client < 0) {
      perror("accept");
      continue;
    }

    try {
      // read length
      uint32_t len;
      recv_all(client, reinterpret_cast<uint8_t *>(&len), sizeof(len));

      // (optional but smart) sanity check
      if (len > 10 * 1024 * 1024) {
        throw std::runtime_error("message too large");
      }

      // read message
      std::vector<uint8_t> msg(len);
      recv_all(client, msg.data(), len);

      // sign
      std::array<uint8_t, crypto_sign_BYTES> sig{};
      crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(),
                           sk.data());

      // send signature
      send_all(client, sig.data(), sig.size());

    } catch (const std::exception &e) {
      std::cerr << "client error: " << e.what() << "\n";
    }

    close(client);
  }

  cleanup();
  return 0;
}
