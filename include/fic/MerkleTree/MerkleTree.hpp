#pragma once
#include "include/fic/Engines/IHashEngine.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

using Hash32 = std::array<uint8_t, 32>;

/**
 * @brief Describes a single changed chunk between two Merkle trees.
 *
 * Produced by MerkleTree::diff(). Each record identifies a leaf that
 * differed, its byte range within the original data, and both the
 * old and new content hashes so callers can verify or apply the delta
 * without re-reading unchanged chunks.
 */
struct Diff {
  size_t chunk_id;
  uint64_t offset;
  uint64_t size;
  Hash32 old_hash;
  Hash32 new_hash;
};

/**
 * @brief Serialisable representation of a fully built Merkle tree.
 *
 * Nodes are stored in a flat breadth-first array (BFS order) so that
 * child indices are computable without pointers:
 *
 *   left child  of node[i] = node[2i + 1]
 *   right child of node[i] = node[2i + 2]
 *
 * The root is always nodes[0]. Leaves occupy the right half of the
 * array starting at nodes[leaf_start()].
 *
 * @note Constructed exclusively by MerkleTree::build(); do not
 *       populate nodes manually or the BFS invariant will be violated.
 */
struct MerkelTreeData {
  /// Flat BFS-ordered array of all node hashes (internal + leaf).
  /// Index 0 is the root; indices [leaf_start(), nodes.size()) are leaves.
  std::vector<Hash32> nodes;

  /// Number of original leaves passed to MerkleTree::build().
  /// May be less than (nodes.size() - leaf_start()) when the leaf layer
  /// was zero-padded to the next power of two.
  size_t num_leaves;

  /**
   * @brief Return the root hash of the tree.
   * @return nodes[0], or a zeroed Hash32 if the tree is empty.
   */
  [[nodiscard]] Hash32 root() const {
    return nodes.empty() ? Hash32{} : nodes[0];
  }

  /**
   * @brief Return the index of the first leaf in the nodes array.
   *
   * In a complete binary tree stored in BFS order, the leaf layer
   * begins at nodes.size() / 2 (integer division via right-shift).
   *
   * @return Leaf-layer start index.
   */
  [[nodiscard]] size_t leaf_start() const {
    return nodes.size() >> 1;
  }

  [[nodiscard]] Hash32 leaf_at(const size_t &i) const {
    return nodes[leaf_start() + i];
  }
};

/**
 * @brief Immutable Merkle hash tree for content-addressed verification and
 * diff.
 *
 * Builds a binary hash tree over a flat list of leaf hashes, following
 * the leaf/node domain-separation scheme from RFC 6962 §2.1:
 *   leaf hash  = H(0x00 || data)
 *   node hash  = H(0x01 || left || right)
 *
 * Odd-length layers are padded by zero-duplicating the last leaf (rather
 * than promoting it), keeping tree depth uniform and simplifying proof
 * generation.
 *
 * @note All methods are static; the class is a pure algorithm namespace
 *       and is not meant to be instantiated.
 *
 * @see RFC 6962 §2.1  — leaf/node hash separation
 * @see IHashEngine     — pluggable hash algorithm interface
 * @see MerkelTreeData  — serialisable tree representation
 */
class MerkleTree {
public:
  /**
   * @brief Construct a Merkle tree from a flat list of leaf hashes.
   *
   * Each element of @p leaves is domain-separated with the 0x00 prefix
   * before being hashed (RFC 6962 leaf rule). Intermediate nodes are
   * hashed with the 0x01 prefix. If @p leaves has an odd count the last
   * leaf is duplicated so every internal layer has even width.
   *
   * @param leaves  Non-empty ordered list of 32-byte leaf hashes.
   *                The order determines tree topology; reordering
   *                produces a different root hash.
   * @param engine  Hash engine to use for all H() calls.
   * @return        Fully populated MerkelTreeData, including the root
   *                hash and the complete internal node table.
   * @throws std::invalid_argument if @p leaves is empty.
   */
  static MerkelTreeData build(const std::vector<Hash32> &, const IHashEngine &);

  /**
   * @brief Check whether two trees represent identical content.
   *
   * Comparison is performed by root-hash equality only — O(1).
   * Two trees built from the same leaf sequence with the same
   * IHashEngine implementation will always compare equal.
   *
   * @param lhs  First tree.
   * @param rhs  Second tree.
   * @return     true if the root hashes match, false otherwise.
   */
  static bool verify(const MerkelTreeData &, const MerkelTreeData &);

  /**
   * @brief Compute the set of leaves that differ between two trees.
   *
   * Performs a depth-first walk (see walk()), short-circuiting entire
   * subtrees whose root hashes agree. Only leaf-level differences are
   * reported; intermediate node changes are not surfaced directly.
   *
   * Both trees must have been built with the same IHashEngine; mixing
   * engines will produce false positives.
   *
   * @param lhs  Baseline tree (e.g. previously stored snapshot).
   * @param rhs  Candidate tree (e.g. freshly computed tree).
   * @return     Ordered list of Diff records, one per changed leaf index.
   *             Empty if the trees are identical.
   */
  static std::vector<Diff> diff(const MerkelTreeData &, const MerkelTreeData &);

private:
  /**
   * @brief Apply the RFC 6962 leaf-domain prefix before hashing.
   *
   * Computes H(0x00 || leaf) to prevent second-preimage attacks where
   * an internal node value could be mistaken for a valid leaf.
   *
   * @param leaf    Raw 32-byte leaf hash (not yet domain-separated).
   * @param engine  Hash engine.
   * @return        Domain-separated leaf hash.
   */
  static Hash32 hash_leaf(const Hash32 &, const IHashEngine &);

  /**
   * @brief Recursively walk two subtrees and collect differing leaves.
   *
   * Called by diff(). Subtrees whose root hashes match are skipped
   * entirely. Differences are appended to @p out in left-to-right
   * leaf order.
   *
   * @param lhs   Left-hand tree data.
   * @param rhs   Right-hand tree data.
   * @param node  Index into the internal node table for the current
   *              subtree root (0 = overall root).
   * @param out   Accumulator for discovered Diff records (modified
   *              in-place).
   */
  static void walk(const MerkelTreeData &, const MerkelTreeData &, size_t,
                   std::vector<Diff> &);

  /**
   * @brief Combine two child hashes into a parent node hash.
   *
   * Computes H(0x01 || left || right) per the RFC 6962 node rule.
   *
   * @param left    Hash of the left child subtree root.
   * @param right   Hash of the right child subtree root.
   * @param engine  Hash engine.
   * @return        Combined parent hash.
   */
  static Hash32 combine(const Hash32 &, const Hash32 &, const IHashEngine &);
};
