#include <cstdlib>
#include <iostream>
#include <sodium.h>
#include <sstream>
#include <vector>

// base64 encode
std::string base64_encode(const unsigned char *data, size_t len) {
  size_t out_len =
      sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
  std::vector<char> out(out_len);

  sodium_bin2base64(out.data(), out.size(), data, len,
                    sodium_base64_VARIANT_ORIGINAL);

  return std::string(out.data());
}

int main() {
  if (sodium_init() < 0) {
    std::cerr << "sodium_init failed\n";
    return 1;
  }

  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];

  if (crypto_sign_keypair(pk, sk) != 0) {
    std::cerr << "key generation failed\n";
    return 1;
  }

  std::string sk_b64 = base64_encode(sk, sizeof(sk));

  std::stringstream cmd;
  cmd << "security add-generic-password "
      << "-a fic-key "
      << "-s fic-signer "
      << "-w \"" << sk_b64 << "\" "
      << "-U"; // update if exists

  int ret = system(cmd.str().c_str());
  if (ret != 0) {
    std::cerr << "failed to store key in Keychain\n";
    return 1;
  }
  FILE *f = fopen("public.key", "wb");
  fwrite(pk, 1, sizeof(pk), f);
  fclose(f);

  sodium_memzero(sk, sizeof(sk));

  std::cout << "Key stored in macOS Keychain\n";
  return 0;
}
