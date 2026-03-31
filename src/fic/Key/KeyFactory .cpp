#include "include/fic/Key/KeyFactory.hpp"

std::unique_ptr<KeyProvider> KeyFactory::create_key_provider() {
#ifdef FIC_USE_KEYCHAIN
  return std::make_unique<KeyChainProvider>();
#else
  return std::make_unique<FileProvider>();
#endif
}
