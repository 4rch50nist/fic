#pragma once
#include "IHashEngine.hpp"

class SHA512Engine : public IHashEngine {
    public : 
    [[nodiscard]] const char *name() const override
    {
        return "SHA512";
    }
    void hash(const uint8_t *, size_t,
            std::array<uint8_t, 32> &) const override;
};