#include "fic/Engines/BLAKE2bEngine.hpp"
#include "fic/Engines/SHA256Engine.hpp"
#include "fic/Engines/SHA512Engine.hpp"
#include "fic/Manifest/Manifest.hpp"
#include "fic/MerkelTree/MerkelTree.hpp"
#include "fic/Pipeline/Pipeline.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>

// return codes
static constexpr int RC_OK = 0;
static constexpr int RC_MODIFIED = 1;
static constexpr int RC_ERROR = 2;

static void print_usage(const char *prog) {
  std::printf("usage: %s <file> [sha256|sha512|blake2b]\n", prog);
}

static void print_hash(const Hash32 &h) {
  for (auto b : h)
    std::printf("%02x", b);
}

int main(int argc, char **argv) {
  if (argc < 2) {
    print_usage(argv[0]);
    return RC_ERROR;
  }

  const std::string file_path = argv[1];
  const std::string algo_str = argc >= 3 ? argv[2] : "sha256";

  std::unique_ptr<IHashEngine> engine;
  HashAlgo algo;

  if (algo_str == "sha256") {
    engine = std::make_unique<SHA256Engine>();
    algo = HashAlgo::SHA256;
  } else if (algo_str == "sha512") {
    engine = std::make_unique<SHA512Engine>();
    algo = HashAlgo::SHA512;
  } else if (algo_str == "blake2b") {
    engine = std::make_unique<BLAKE2bEngine>();
    algo = HashAlgo::BLAKE2b;
  } else {
    std::printf("error: unknown algorithm '%s'\n", algo_str.c_str());
    print_usage(argv[0]);
    return RC_ERROR;
  }

  const std::string manifest_path = file_path + ".manifest";

  // --- run pipeline ---
  std::printf("hashing: %s\n", file_path.c_str());
  auto pipeline_result = run_pipeline(file_path.c_str(), *engine);

  if (pipeline_result.streamResult != StreamResult::Ok) {
    switch (pipeline_result.streamResult) {
    case StreamResult::ErrorOpen:
      std::printf("error: could not open file '%s'\n", file_path.c_str());
      break;
    case StreamResult::ErrorRead:
      std::printf("error: read error on '%s'\n", file_path.c_str());
      break;
    default:
      std::printf("error: pipeline failed\n");
      break;
    }
    return RC_ERROR;
  }

  std::vector<Hash32> hashes;
  hashes.reserve(pipeline_result.chunks.size());
  for (auto &c : pipeline_result.chunks)
    hashes.push_back(c.hash);

  auto new_tree = MerkelTree::build(hashes, *engine);

  auto old_manifest = read_manifest(manifest_path);

  if (!old_manifest) {
    // first run
    std::printf("no manifest found — first run\n");

    auto manifest = generate_manifest(file_path, pipeline_result.chunks,
                                      new_tree.root(), algo);

    if (!write_manifest(manifest, manifest_path)) {
      std::printf("error: could not write manifest\n");
      return RC_ERROR;
    }

    std::printf("chunks:   %zu\n", pipeline_result.chunks.size());
    std::printf("root:     ");
    print_hash(new_tree.root());
    std::printf("\n");
    std::printf("manifest: %s\n", manifest_path.c_str());
    std::printf("status:   OK\n");

    return RC_OK;

  } else {
    // incremental run

    // rebuild old tree from manifest chunk hashes
    std::vector<Hash32> old_hashes;
    old_hashes.reserve(old_manifest->chunks.size());
    for (auto &c : old_manifest->chunks)
      old_hashes.push_back(c.hash);

    auto old_tree = MerkelTree::build(old_hashes, *engine);

    // compare roots
    if (MerkelTree::verify(old_tree, new_tree)) {
      std::printf("status:   OK — file unchanged\n");
      std::printf("root:     ");
      print_hash(new_tree.root());
      std::printf("\n");
      return RC_OK;

    } else {
      // diff to find exactly what changed
      auto diffs = MerkelTree::diff(old_tree, new_tree);

      std::printf("status:   MODIFIED\n");
      std::printf("changed:  %zu chunk(s)\n", diffs.size());
      std::printf("\n");

      for (auto &d : diffs) {
        // look up offset + size from manifest
        auto &old_chunk = old_manifest->chunks[d.chunk_id];
        std::printf("  chunk %zu\n", d.chunk_id);
        std::printf("    offset: %llu\n", (unsigned long long)old_chunk.offset);
        std::printf("    size:   %llu\n", (unsigned long long)old_chunk.size);
        std::printf("    old:    ");
        print_hash(d.old_hash);
        std::printf("\n");
        std::printf("    new:    ");
        print_hash(d.new_hash);
        std::printf("\n\n");
      }

      // update manifest with new hashes
      auto new_manifest = generate_manifest(file_path, pipeline_result.chunks,
                                            new_tree.root(), algo);

      if (!write_manifest(new_manifest, manifest_path)) {
        std::printf("error: could not write manifest\n");
        return RC_ERROR;
      }

      return RC_MODIFIED;
    }
  }
}
