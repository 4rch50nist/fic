#include "fic/Key/KeyProvider.cpp"

class KeyChainProvider : public KeyProvider {
public:
  bool load_secret_key(std::array<uint8_t, crypto_sign_SECRETKEYBYTES> &out) {
    FILE *pipe = popen(
        "security find-generic-password -a fic-key -s fic-signer -w", "r");

    if (!pipe) {
      throw std::runtime_error("KeyChainProvider: failed to access Keychain");
    }

    std::string b64;
    char buffer[256];

    while (fgets(buffer, sizeof(buffer), pipe)) {
      b64 += buffer;
    }

    pclose(pipe);

    if (b64.empty()) {
      throw std::runtime_error("KeyChainProvider: empty key from Keychain");
    }

    if (!b64.empty() && b64.back() == '\n') {
      b64.pop_back();
    }

    size_t decoded_len = 0;

    if (sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(),
                          nullptr, &decoded_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
      throw std::runtime_error("KeyChainProvider: base64 decode failed");
    }

    if (decoded_len != crypto_sign_SECRETKEYBYTES) {
      throw std::runtime_error("KeyChainProvider: invalid key size");
    }

    return true;
  }
};
