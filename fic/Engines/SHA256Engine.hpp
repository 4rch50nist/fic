#pragma once
#include "../../IHashEngine.hpp"
#include <openssl/sha.h>

class SHA256Engine : public IHashEngine {
public:
  const char *name() const override { return "SHA256"; }

  void hash(const uint8_t *data, size_t size,
            std::array<uint8_t, 32> &out) const override {
    SHA256(data, size, out.data());
  }
};
