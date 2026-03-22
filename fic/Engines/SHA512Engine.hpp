#pragma once
#include "../../IHashEngine.hpp"
#include <cstring>
#include <openssl/evp.h>

class SHA512Engine : public IHashEngine {
public:
  const char *name() const override { return "SHA512"; }

  void hash(const uint8_t *data, size_t size,
            std::array<uint8_t, 32> &out) const override {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 32;
    EVP_DigestInit_ex(ctx, EVP_sha512_256(), nullptr);
    EVP_DigestUpdate(ctx, data, size);
    EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);
  }
};
