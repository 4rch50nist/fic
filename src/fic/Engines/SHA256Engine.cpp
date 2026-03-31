#include "include/fic/Engines/SHA256Engine.hpp"
#include <openssl/evp.h>


void SHA256Engine::hash(const uint8_t *data,const size_t size,
                        std::array<uint8_t, 32> &out) const {
  SHA256(data, size, out.data());
}