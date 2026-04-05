#pragma once
#include "include/fic/Key/KeyProvider.hpp"
namespace KeyFactory {
std::unique_ptr<KeyProvider> create_key_provider();

}; // namespace KeyFactory
