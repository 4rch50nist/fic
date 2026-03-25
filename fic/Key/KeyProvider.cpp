#include <cstdint>
#include <vector>
class KeyProvider {
public:
  virtual std::vector<uint8_t> load_secret_key() = 0;
  virtual ~KeyProvider() = default;
};
