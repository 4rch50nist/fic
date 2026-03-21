#pragma once
#include "../IHashEngine.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

using Hash32 = std::array<uint8_t, 32>;
class MerkelTree {
public:
  static Hash32 build(const std::vector<Hash32> &leaves,
                      const IHashEngine &engine) {
    if (leaves.empty())
      return Hash32{};
    if (leaves.size() == 1)
      return hash_leaf(leaves[0], engine);

    std::vector<Hash32> level;
    level.reserve(leaves.size());

    for (auto &leaf : leaves)
      level.push_back(hash_leaf(leaf, engine));

    while (level.size() > 1) {
      std::vector<Hash32> next;
      next.reserve((level.size() + 1) >> 1);

      for (size_t i = 0; i < level.size(); i += 2) {
        if (i + 1 < level.size())
          next.push_back(combine(level[i], level[i + 1], engine));
        else
          next.push_back(combine(level[i], level[i], engine));
      }

      level = std::move(next);
    }

    return level[0];
  }

  static bool verify(const std::vector<Hash32> &leaves, const Hash32 &against,
                     const IHashEngine &engine) {
    return build(leaves, engine) == against;
  }

private:
  static Hash32 hash_leaf(const Hash32 &leaf, const IHashEngine &engine) {
    uint8_t buf[33];
    buf[0] = 0x00;
    std::memcpy(buf + 1, leaf.data(), 32);
    Hash32 out;
    engine.hash(buf, 33, out);
    return out;
  }

  static Hash32 combine(const Hash32 &left, const Hash32 &right,
                        const IHashEngine &engine) {
    uint8_t buf[65];
    buf[0] = 0x01;
    std::memcpy(buf + 1, left.data(), 32);
    std::memcpy(buf + 33, right.data(), 32);
    Hash32 out;
    engine.hash(buf, 65, out);
    return out;
  }
};
