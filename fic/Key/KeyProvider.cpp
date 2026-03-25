#include <cstdint>
#include <sodium.h>
#include <vector>
class KeyProvider {
public:
  virtual bool
  load_secret_key(std::array<uint8_t, crypto_sign_SECRETKEYBYTES> &out) = 0;
  virtual std::vector<uint8_t> load_public_key() { return {}; }
  virtual ~KeyProvider() = default;
};
