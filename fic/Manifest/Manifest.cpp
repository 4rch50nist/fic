#include "Manifest.hpp"
#include <unordered_set>

/// Generates a Manifest according to some schema.
Manifest generate_manifest(const std::string &file_path,
                           const std::vector<Chunk> &chunks, const Hash32 &root,
                           HashAlgo algo) {
  Manifest m;

  m.file_path = file_path;
  m.header.algo = algo;
  m.header.num_chunks = chunks.size();
  m.header.chunk_size = CHUNK_SIZE;
  m.header.generated_at = (uint64_t)std::time(nullptr);
  m.header.root_hash = root;

  // magic and version already defaulted in ManifestHeader struct
  // no need to set them here
  m.chunks.reserve(chunks.size());
  for (auto &chunk : chunks) {
    m.chunks.push_back(ManifestChunk{.chunk_id = chunk.chunk_id,
                                     .offset = chunk.offset,
                                     .size = (uint64_t)chunk.size,
                                     .hash = chunk.hash});
  }

  return m;
}

/// Write the manifest to the .manifest file. This will return false if
/// it cannot write all the Manifest information to the file, or
/// If it cannot open the file at the path,
bool write_manifest(const Manifest &m, const std::string &path) {

  /// First we write to some temporary file.
  std::string tmp_path = path + ".tmp";

  std::FILE *f = std::fopen(tmp_path.c_str(), "wb");
  if (!f)
    return false;

  // write header
  if (std::fwrite(&m.header, sizeof(ManifestHeader), 1, f) != 1) {
    std::fclose(f);
    std::remove(tmp_path.c_str());
    return false;
  }

  // write path length + path
  uint16_t path_len = (uint16_t)m.file_path.size();
  if (std::fwrite(&path_len, sizeof(uint16_t), 1, f) != 1) {
    std::fclose(f);
    std::remove(tmp_path.c_str());
    return false;
  }
  if (std::fwrite(m.file_path.c_str(), sizeof(char), path_len, f) != path_len) {
    std::fclose(f);
    std::remove(tmp_path.c_str());
    return false;
  }

  // write chunks
  for (auto &c : m.chunks) {
    if (std::fwrite(&c, sizeof(ManifestChunk), 1, f) != 1) {
      std::fclose(f);
      std::remove(tmp_path.c_str());
      return false;
    }
  }

  // write the signature
  if (fwrite(m.signature.data(), 1, 64, f) != 64) {
    std::printf("Writing signature\n");
    std::fclose(f);
    std::remove(tmp_path.c_str());
    return false;
  }

  // flush userspace → kernel
  std::fflush(f);

  // flush kernel → disk
  fsync(fileno(f));

  std::fclose(f);

  // atomic replace
  if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
    std::remove(tmp_path.c_str());
    return false;
  }

  return true;
}

std::optional<Manifest> read_manifest(const std::string &path) {

  std::remove((path + ".tmp").c_str());

  std::FILE *f = std::fopen(path.c_str(), "rb");
  if (!f)
    return std::nullopt;

  Manifest m;

  // read header
  if (std::fread(&m.header, sizeof(ManifestHeader), 1, f) != 1) {
    std::fclose(f);
    return std::nullopt;
  }

  // sanity checks
  if (m.header.magic != MANIFEST_MAGIC) {
    std::fclose(f);
    return std::nullopt;
  }
  if (m.header.version != MANIFEST_VERSION) {
    std::fclose(f);
    return std::nullopt;
  }

  // read path length
  uint16_t path_len = 0;
  if (std::fread(&path_len, sizeof(uint16_t), 1, f) != 1) {
    std::fclose(f);
    return std::nullopt;
  }

  // read path string
  m.file_path.resize(path_len);
  if (std::fread(m.file_path.data(), sizeof(char), path_len, f) != path_len) {
    std::fclose(f);
    return std::nullopt;
  }

  // read chunks
  m.chunks.resize(m.header.num_chunks);
  for (size_t i = 0; i < m.header.num_chunks; i++) {
    if (std::fread(&m.chunks[i], sizeof(ManifestChunk), 1, f) != 1) {
      std::fclose(f);
      return std::nullopt;
    }
  }

  // read signature
  if (std::fread(&m.signature, sizeof(m.signature), 1, f) != 1) {
    std::fclose(f);
    return std::nullopt;
  }

  std::fclose(f);
  return m;
}

std::vector<size_t> compare_manifest(const Manifest &old_manifest,
                                     const std::vector<Chunk> &new_chunks) {
  std::vector<size_t> changed;

  // build lookup — chunk_id → old hash
  std::unordered_map<uint64_t, Hash32> old_hashes;
  old_hashes.reserve(old_manifest.chunks.size());
  for (auto &c : old_manifest.chunks)
    old_hashes[c.chunk_id] = c.hash;

  // check new chunks against old
  std::unordered_set<uint64_t> seen;
  seen.reserve(new_chunks.size());

  for (auto &c : new_chunks) {
    seen.insert(c.chunk_id);
    auto it = old_hashes.find(c.chunk_id);
    if (it == old_hashes.end()) {
      // new chunk — file grew
      changed.push_back(c.chunk_id);
    } else if (it->second != c.hash) {
      // hash differs — content changed
      changed.push_back(c.chunk_id);
    }
    // hash matches — unchanged, skip
  }

  // check old chunks not in new — file shrank
  for (auto &c : old_manifest.chunks) {
    if (seen.find(c.chunk_id) == seen.end())
      changed.push_back(c.chunk_id);
  }

  return changed;
}
std::vector<uint8_t> build_signing_message(const ManifestHeader &h) {
  std::vector<uint8_t> buf;

  auto append = [&](const void *data, size_t len) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
    buf.insert(buf.end(), p, p + len);
  };

  append(&h.magic, sizeof(h.magic));
  append(&h.version, sizeof(h.version));
  append(&h.algo, sizeof(h.algo));
  append(&h.chunk_size, sizeof(h.chunk_size));
  append(&h.num_chunks, sizeof(h.num_chunks));
  append(h.root_hash.data(), h.root_hash.size());
  append(&h.generated_at, sizeof(h.generated_at));

  return buf;
}
