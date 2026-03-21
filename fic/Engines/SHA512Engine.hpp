#pragma once
#include "../IHashEngine.hpp"
#include <openssl/sha.h>
#include <cstring>

class SHA512Engine : public IHashEngine {
public:
    const char* name() const override {
        return "SHA512";
    }

    void hash(const uint8_t* data, size_t size,
              std::array<uint8_t, 32>& out) const override {
        uint8_t tmp[64];
        SHA512(data, size, tmp);
        std::memcpy(out.data(), tmp, 32);
    }
};