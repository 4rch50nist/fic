#pragma once
#include <array>
#include <cstdint>
#include <sodium.h>

class KeyProvider {
public:
  virtual bool
  load_secret_key(std::array<uint8_t, crypto_sign_SECRETKEYBYTES> &) = 0;
  virtual bool generate_secret_key() = 0;
  virtual bool
  load_public_key(std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> &) = 0;
  virtual ~KeyProvider() = default;
};
