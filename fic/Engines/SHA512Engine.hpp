#pragma once
#include "../../IHashEngine.hpp"
#include <openssl/evp.h>
class SHA512Engine : public IHashEngine {
    public : 
    [[nodiscard]] const char *name() const override;
    void hash(const uint8_t *, size_t sze,
            std::array<uint8_t, 32> &ot) const override;
};