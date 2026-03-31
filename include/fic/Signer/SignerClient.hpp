#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

std::array<uint8_t, 64>
request_signature_from_host(const std::vector<uint8_t> &message,
                            const std::string &socket_path);
bool verify_signature(const std::vector<uint8_t> &msg,
                      const std::array<uint8_t, 64> &sig);
bool keys_exist();


void recv_all(int , uint8_t *, size_t );
void send_all(int, uint8_t *, size_t );