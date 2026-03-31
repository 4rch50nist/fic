#include "SHA256Engine.hpp"

const char *SHA256Engine::name() const { return "SHA256"; }

void SHA256Engine::hash(const uint8_t *data,const size_t size,
                        std::array<uint8_t, 32> &out) const {
  SHA256(data, size, out.data());
}