#pragma once
#include "../IHashEngine.hpp"
#include <openssl/evp.h>
#include <cstring>

class BLAKE2bEngine : public IHashEngine {
public:
    const char* name() const override {
        return "BLAKE2b";
    }

    void hash(const uint8_t* data, size_t size,
              std::array<uint8_t, 32>& out) const override {
        uint8_t tmp[64];
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);
        EVP_DigestUpdate(ctx, data, size);
        unsigned int len = 64;
        EVP_DigestFinal_ex(ctx, tmp, &len);
        EVP_MD_CTX_free(ctx);
        std::memcpy(out.data(), tmp, 32);
    }
};  