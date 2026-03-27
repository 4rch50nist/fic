#pragma once

#include "../IO/ChunkReader.hpp"
#include "../MerkelTree/MerkelTreeData.hpp"
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

static constexpr uint32_t MANIFEST_MAGIC = 0xF1C0FFEE;
static constexpr uint8_t MANIFEST_VERSION = 1;

enum class HashAlgo : uint8_t { SHA256 = 0, SHA512 = 1, BLAKE2b = 2 };

struct ManifestChunk {
  uint64_t chunk_id;
  uint64_t offset;
  uint64_t size;
  Hash32 hash;
};

struct ManifestHeader {
  uint32_t magic = MANIFEST_MAGIC;
  uint8_t version = MANIFEST_VERSION;
  HashAlgo algo = HashAlgo::SHA256;
  uint64_t chunk_size = 0;
  uint64_t num_chunks = 0;
  Hash32 root_hash = {};
  uint64_t generated_at = 0;
};

struct Manifest {
  ManifestHeader header;
  std::string file_path;
  std::vector<ManifestChunk> chunks;
  std::array<uint8_t, 64> signature; /// Ed25519
};

Manifest generate_manifest(const std::string &file_path,
                           const std::vector<Chunk> &chunks, const Hash32 &root,
                           HashAlgo algo = HashAlgo::SHA256);

bool write_manifest(const Manifest &m, const std::string &path);

std::optional<Manifest> read_manifest(const std::string &path);

std::vector<size_t> compare_manifest(const Manifest &old_manifest,
                                     const std::vector<Chunk> &new_chunks);
std::vector<uint8_t> build_signing_message(const ManifestHeader &h);
