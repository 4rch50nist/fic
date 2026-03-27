#include "KeyChainProvider.hpp"

#ifdef FIC_USE_KEYCHAIN
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <Security/Security.h>
#pragma clang diagnostic pop
#include <cstring>
#include <fstream>
#include <iostream>
#include <sodium.h>

static constexpr const char SERVICE[] = "fic-signer";
static constexpr const char ACCOUNT[] = "fic-key";

bool KeyChainProvider::load_secret_key(
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> &out) {

  void *data = nullptr;
  UInt32 length = 0;

  OSStatus status = SecKeychainFindGenericPassword(
      nullptr, sizeof(SERVICE) - 1, SERVICE, sizeof(ACCOUNT) - 1, ACCOUNT,
      &length, &data, nullptr);

  if (status != errSecSuccess) {
    throw std::runtime_error("KeyChainProvider: failed to access Keychain");
  }

  if (length != crypto_sign_SECRETKEYBYTES) {
    SecKeychainItemFreeContent(nullptr, data);
    throw std::runtime_error("KeyChainProvider: invalid key size");
  }

  std::memcpy(out.data(), data, length);
  SecKeychainItemFreeContent(nullptr, data);

  return true;
}

bool KeyChainProvider::generate_secret_key() {
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pk{};
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> sk{};

  if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
    throw std::runtime_error("key generation failed");
  }

  OSStatus status = SecKeychainAddGenericPassword(
      nullptr, sizeof(SERVICE) - 1, SERVICE, sizeof(ACCOUNT) - 1, ACCOUNT,
      sk.size(), sk.data(), nullptr);

  if (status == errSecDuplicateItem) {
    SecKeychainItemRef item = nullptr;

    status = SecKeychainFindGenericPassword(nullptr, sizeof(SERVICE) - 1,
                                            SERVICE, sizeof(ACCOUNT) - 1,
                                            ACCOUNT, nullptr, nullptr, &item);

    if (status != errSecSuccess) {
      sodium_memzero(sk.data(), sk.size());
      throw std::runtime_error("failed to find existing key for update");
    }

    status = SecKeychainItemModifyAttributesAndData(item, nullptr, sk.size(),
                                                    sk.data());

    if (item)
      CFRelease(item);
  }

  if (status != errSecSuccess) {
    sodium_memzero(sk.data(), sk.size());
    throw std::runtime_error("failed to store key in Keychain");
  }

  sodium_memzero(sk.data(), sk.size());

  std::cout << "Key stored in macOS Keychain\n";
  return true;
}

bool KeyChainProvider::load_public_key(
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> &pk) {
  std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk;

  if (!load_secret_key(sk)) {
    return false;
  }

  crypto_sign_ed25519_sk_to_pk(pk.data(), sk.data());
  sodium_memzero(sk.data(), sk.size());
  return true;
}
#endif
