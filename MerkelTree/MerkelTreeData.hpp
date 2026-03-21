#pragma once
#include <array>
#include <vector>

using Hash32 = std::array<uint8_t, 32>;
struct MerkelTreeData {
  std::vector<Hash32> nodes;
  size_t num_leaves;

  Hash32 root() const { return nodes.empty() ? Hash32{} : nodes[0]; }

  size_t leaf_start() const { return nodes.size() >> 1; }

  Hash32 leaf_at(size_t &i) const { return nodes[leaf_start() + i]; }
};
