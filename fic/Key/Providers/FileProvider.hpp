#pragma once
#include "fic/Key/KeyProvider.hpp"
#include <array>
#include <cstdint>
#include <sodium.h>

class FileProvider : public KeyProvider {
public:
  bool load_secret_key(
      std::array<uint8_t, crypto_sign_SECRETKEYBYTES> &key) override {
    FILE *f = fopen("secret.key", "rb");
    if (!f)
      throw std::runtime_error("missing secret.key");

    fread(key.data(), 1, key.size(), f);
    fclose(f);
    return true;
  }
  bool generate_secret_key() override { return true; }
  bool load_public_key(
      std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> &key) override {
    return true;
  }
};
