#include "include/fic/MerkleTree/MerkleTree.hpp"
#include <bit>
#include <cstdint>
#include <cstring>
#include <vector>

/// The Merkle Tree is stored as a heap (2i+1, 2i+2) since in general
/// Merkle Trees are complete binary trees.
MerkelTreeData MerkleTree::build(const std::vector<Hash32> &leaves,
                                 const IHashEngine &engine) {
  /// If empty, return empty root
  if (leaves.empty())
    return MerkelTreeData{{Hash32{}}, 0};

  /// get bit_ceil and the start of leaves
  const size_t pow = std::bit_ceil(leaves.size());
  const size_t leaf_start = pow - 1;

  MerkelTreeData tree;
  tree.num_leaves = leaves.size();
  tree.nodes.resize((pow << 1) - 1);

  /// Hash real leaves
  for (size_t i = 0; i < leaves.size(); i++)
    tree.nodes[i + leaf_start] = hash_leaf(leaves[i], engine);

  /// Pad missing leaves with zero hash — avoids duplicate-leaf root collision
  for (size_t i = leaves.size(); i < pow; i++)
    tree.nodes[leaf_start + i] = Hash32{};

  /// Build internal nodes bottom-up
  /// Uses i-- > 0 to safely handle unsigned wraparound at i=0
  if (leaf_start > 0) {
    for (size_t i = leaf_start; i-- > 0;) {
      tree.nodes[i] =
          combine(tree.nodes[(i << 1) + 1], tree.nodes[(i << 1) + 2], engine);
    }
  }

  return tree;
}

/// Verify the root of the previous with the root of the new one.
bool MerkleTree::verify(const MerkelTreeData &old_tree,
                        const MerkelTreeData &new_tree) {
  return old_tree.root() == new_tree.root();
}

/// Generate diff between old and new by walking the tree and comparing
/// subtree hashes — prunes unchanged subtrees early for O(k log N) behaviour.
std::vector<Diff> MerkleTree::diff(const MerkelTreeData &old_tree,
                                   const MerkelTreeData &new_tree) {
  std::vector<Diff> diffs;
  if (!old_tree.nodes.empty() && !new_tree.nodes.empty())
    walk(old_tree, new_tree, 0, diffs);
  return diffs;
}

Hash32 MerkleTree::hash_leaf(const Hash32 &leaf, const IHashEngine &engine) {
  uint8_t buf[33];
  /// Prefix leaves with 0x00 to prevent second-preimage attacks
  buf[0] = 0x00;
  std::memcpy(buf + 1, leaf.data(), 32);
  Hash32 out;
  engine.hash(buf, 33, out);
  return out;
}

void MerkleTree::walk(const MerkelTreeData &old_tree,
                      const MerkelTreeData &new_tree, const size_t i,
                      std::vector<Diff> &diffs) {
  /// Prune subtree early if hashes match — avoids O(N) full traversal
  if (old_tree.nodes[i] == new_tree.nodes[i])
    return;

  if (const size_t ls = old_tree.leaf_start(); i >= ls) {
    if (const size_t idx = i - ls;
        idx < old_tree.num_leaves && idx < new_tree.num_leaves) {
      diffs.push_back(Diff{.chunk_id = idx,
                           .old_hash = old_tree.nodes[i],
                           .new_hash = new_tree.nodes[i]});
    }
    return;
  }

  walk(old_tree, new_tree, 2 * i + 1, diffs);
  walk(old_tree, new_tree, 2 * i + 2, diffs);
}

/// Combine left and right child hashes into a 65-byte buffer and hash it.
/// Inner nodes are prefixed with 0x01 to prevent second-preimage attacks.
Hash32 MerkleTree::combine(const Hash32 &left, const Hash32 &right,
                           const IHashEngine &engine) {
  uint8_t buf[65];
  /// Prefix inner nodes with 0x01 to prevent attacks
  buf[0] = 0x01;
  std::memcpy(buf + 1, left.data(), 32);
  std::memcpy(buf + 33, right.data(), 32);
  Hash32 out;
  engine.hash(buf, 65, out);
  return out;
}
