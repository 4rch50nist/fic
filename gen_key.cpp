#include <sodium.h>
#include <fstream>

int main() {
    sodium_init();

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair(pk, sk);

    std::ofstream("public.key", std::ios::binary).write((char*)pk, sizeof(pk));
    std::ofstream("secret.key", std::ios::binary).write((char*)sk, sizeof(sk));
}
