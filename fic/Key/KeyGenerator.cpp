#include "KeyFactory.hpp"
#include <cstdlib>
#include <iostream>
#include <sodium.h>

int main() {
  if (sodium_init() < 0) {
    std::cerr << "sodium_init failed\n";
    return 1;
  }

  KeyFactory::create_key_provider()->generate_secret_key();
}
