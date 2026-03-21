  #pragma once
#include <array>
#include <cstddef>
#include <cstdint>

class IHashEngine {
public:
  virtual ~IHashEngine() = default;

  virtual void hash(const uint8_t *data, size_t size,
                    std::array<uint8_t, 32> &out) const = 0;

  virtual const char *name() const = 0;
};
