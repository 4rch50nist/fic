#pragma once
#include "../../IHashEngine.hpp"
#include "MerkelTreeData.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <vector>

struct Diff {
  size_t chunk_id;
  uint64_t offset;
  uint64_t size;
  Hash32 old_hash;
  Hash32 new_hash;
};

///
/// Read https://datatracker.ietf.org/doc/html/rfc6962 for information on
/// leaf(0x00) and node(0x01) logic it is under (2.1) Merkle Hash Trees
/// and for general overview of Merkle Tree :
/// https://ieeexplore.ieee.org/document/9545917 and for further reading (Verkle
/// Tree on limited-bandwith networks you can refer):
/// https://math.mit.edu/research/highschool/primes/materials/2018/Kuszmaul.pdf
///
///
/// In general though, for odd leafs we use the simpler strategy of
/// even-duplication rather than premature promotion.
///
class MerkelTree {
public:
  /// The Merle Tree is stored as a heap (2i +1, 2i+2) since in general
  /// Merkle Trees are complete binary trees.
  static MerkelTreeData build(const std::vector<Hash32> &leaves,
                              const IHashEngine &engine) {

    /// If empty, return empty root
    if (leaves.empty())
      return MerkelTreeData{{Hash32{}}, 0};

    /// get bit_ceil and the start of leaves;
    size_t pow = std::bit_ceil(leaves.size());
    size_t leaf_start = pow - 1;

    MerkelTreeData tree;
    tree.num_leaves = leaves.size();
    tree.nodes.resize((pow << 1) - 1);

    for (size_t i = 0; i < leaves.size(); i++)
      tree.nodes[i + leaf_start] = hash_leaf(leaves[i], engine);

    for (size_t i = leaves.size(); i < pow; i++) {
      tree.nodes[leaf_start + i] = hash_leaf(leaves.back(), engine);
    }

    if (leaf_start > 0) {
      for (size_t i = leaf_start - 1; i < leaf_start; i--) {
        tree.nodes[i] =
            combine(tree.nodes[(i << 1) + 1], tree.nodes[(i << 1) + 2], engine);
      }
    }
    return tree;
  }

  /// Verify the root of the previous with the root of the new one.
  static bool verify(const MerkelTreeData &old_tree,
                     const MerkelTreeData &new_tree) {
    return old_tree.root() == new_tree.root();
  }

  /// Generate diff between old and new by walking the tree and comparing
  /// children.
  static std::vector<Diff> diff(const MerkelTreeData &old_tree,
                                const MerkelTreeData &new_tree) {
    std::vector<Diff> diffs;
    if (!old_tree.nodes.empty() && !new_tree.nodes.empty())
      walk(old_tree, new_tree, 0, diffs);
    return diffs;
  }

private:
  static Hash32 hash_leaf(const Hash32 &leaf, const IHashEngine &engine) {
    uint8_t buf[33];

    /// Prefix leafs with 0x00 to stop attack
    buf[0] = 0x00;
    std::memcpy(buf + 1, leaf.data(), 32);
    Hash32 out;
    engine.hash(buf, 33, out);
    return out;
  }

  static void walk(const MerkelTreeData &old_tree,
                   const MerkelTreeData &new_tree, size_t i,
                   std::vector<Diff> &diffs) {
    if (old_tree.root() == new_tree.root())
      return;

    size_t ls = old_tree.leaf_start();

    if (i >= ls) {
      size_t idx = i - ls;
      if (idx < old_tree.num_leaves && idx < new_tree.num_leaves) {
        diffs.push_back(Diff{.chunk_id = idx,
                             .old_hash = old_tree.nodes[i],
                             .new_hash = new_tree.nodes[i]});
      }
      return;
    }

    walk(old_tree, new_tree, 2 * i + 1, diffs);
    walk(old_tree, new_tree, 2 * i + 2, diffs);
  }

  /// Combined 32b left right child and spit out 65b concatenated-hashed output.
  static Hash32 combine(const Hash32 &left, const Hash32 &right,
                        const IHashEngine &engine) {
    uint8_t buf[65];

    // prefix inner nodes with 0x01 to prevent attacks;
    buf[0] = 0x01;
    std::memcpy(buf + 1, left.data(), 32);
    std::memcpy(buf + 33, right.data(), 32);
    Hash32 out;
    engine.hash(buf, 65, out);
    return out;
  }
};
