#pragma once
#include "Providers/FileProvider.hpp"
#ifdef FIC_USE_KEYCHAIN
#include "Providers/KeyChainProvider.hpp"
#endif
#include <memory>

namespace KeyFactory {
std::unique_ptr<KeyProvider> create_key_provider();

}; // namespace KeyFactory
std::unique_ptr<KeyProvider> KeyFactory::create_key_provider() {
#ifdef FIC_USE_KEYCHAIN
  return std::make_unique<KeyChainProvider>();
#else
  return std::make_unique<FileProvider>();
#endif
}
