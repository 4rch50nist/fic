#pragma once
#include "include/fic/Engines/IHashEngine.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

using Hash32 = std::array<uint8_t, 32>;

struct Diff {
  size_t chunk_id;
  uint64_t offset;
  uint64_t size;
  Hash32 old_hash;
  Hash32 new_hash;
};

struct MerkelTreeData {
  std::vector<Hash32> nodes;
  size_t num_leaves;

  [[nodiscard]] Hash32 root() const {
    return nodes.empty() ? Hash32{} : nodes[0];
  }

  [[nodiscard]] size_t leaf_start() const { return nodes.size() >> 1; }

  [[nodiscard]] Hash32 leaf_at(const size_t &i) const {
    return nodes[leaf_start() + i];
  }
};

///
/// Read https://datatracker.ietf.org/doc/html/rfc6962 for information on
/// leaf(0x00) and node(0x01) logic it is under (2.1) Merkle Hash Trees
/// and for general overview of Merkle Tree :
/// https://ieeexplore.ieee.org/document/9545917 and for further reading (Verkle
/// Tree on limited-bandwidth networks you can refer):
/// https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf
///
///
/// In general though, for odd leafs we use the simpler strategy of
/// even-duplication rather than premature promotion.
///
class MerkleTree {
public:
  static MerkelTreeData build(const std::vector<Hash32> &, const IHashEngine &);
  static bool verify(const MerkelTreeData &, const MerkelTreeData &);

  static std::vector<Diff> diff(const MerkelTreeData &, const MerkelTreeData &);

private:
  static Hash32 hash_leaf(const Hash32 &, const IHashEngine &);
  static void walk(const MerkelTreeData &, const MerkelTreeData &, size_t,
                   std::vector<Diff> &);

  static Hash32 combine(const Hash32 &, const Hash32 &, const IHashEngine &);
};
