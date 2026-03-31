#include "include/fic/Engines/BLAKE2bEngine.hpp"
#include <openssl/evp.h>


  void BLAKE2bEngine::hash(const uint8_t *data, const size_t size,
            std::array<uint8_t, 32> &out) const {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int len = 32;
    EVP_DigestInit_ex(ctx, EVP_blake2s256(), nullptr);
    EVP_DigestUpdate(ctx, data, size);
    EVP_DigestFinal_ex(ctx, out.data(), &len);
    EVP_MD_CTX_free(ctx);
}
