#pragma once

#include "fic/Key/KeyProvider.hpp"
#include <array>
#include <cstdint>
#include <sodium.h>

class KeyChainProvider : public KeyProvider {
public:
  bool load_secret_key(
      std::array<uint8_t, crypto_sign_SECRETKEYBYTES> &out) override;

  bool generate_secret_key() override;
  bool load_public_key(
      std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> &out) override;
};
