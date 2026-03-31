#pragma once
#include "IHashEngine.hpp"

class BLAKE2bEngine : public IHashEngine {
    public :
    [[nodiscard]] const char *name() const override
    {
        return "BLAKE2b";
    };
    void hash ( const uint8_t *, size_t, std::array<uint8_t, 32> &out) const override;
};
// ..