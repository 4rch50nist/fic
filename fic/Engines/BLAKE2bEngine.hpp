#pragma once
#include "../../IHashEngine.hpp"
#include <openssl/evp.h>

class BLAKE2bEngine : public IHashEngine {
    public :
    [[nodiscard]] const char *name() const override;
    void hash ( const uint8_t *, size_t, std::array<uint8_t, 32> &out) const override;
};