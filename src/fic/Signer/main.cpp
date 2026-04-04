#include "include/fic/IO/PidGuard.hpp"
#include "include/fic/Signer/SignerServer.hpp"
#include <csignal>
#include <iostream>
#include <sodium.h>

static SignerServer *g_server = nullptr;

std::string_view SOCKET_PATH = "/tmp/fic_file_signer.sock";
std::string_view IPC_PATH = "/tmp/fic_file_ipc.sock";

void signal_handler(int) {
  if (g_server)
    g_server->stop();
}

int main() {
  if (sodium_init() < 0) {
    std::cerr << "libsodium init failed\n";
    return 1;
  }

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  try {
    PidGuard pid_guard("/tmp/fic_signer.pid");
    SignerServer server(SOCKET_PATH.data(), IPC_PATH.data());
    g_server = &server;
    server.run();
    g_server = nullptr;
  } catch (const std::exception &e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return 1;
  }

  return 0;
}
