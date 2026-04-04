#include "include/fic/Key/KeyFactory.hpp"
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

bool notify_keys_changed() {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return false;

  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, "/tmp/fic_file_ipc.sock",
               sizeof(addr.sun_path) - 1);

  if (connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    // signer not running — not necessarily an error
    close(fd);
    return false;
  }

  const char *msg = "keys_changed";
  write(fd, msg, std::strlen(msg));
  close(fd);
  return true;
}

int main() {
  if (sodium_init() < 0) {
    std::cerr << "sodium_init failed\n";
    return 1;
  }

  KeyFactory::create_key_provider()->generate_secret_key();

  if (notify_keys_changed()) {
    std::cout << "Signer notified — keys reloaded.\n";
  } else {
    std::cout << "Signer not running — keys will load on next startup.\n";
  }

  return 0;
}
