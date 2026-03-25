#include "fic/Engines/BLAKE2bEngine.hpp"
#include "fic/Engines/SHA256Engine.hpp"
#include "fic/Engines/SHA512Engine.hpp"
#include "fic/Manifest/Manifest.hpp"
#include "fic/MerkelTree/MerkelTree.hpp"
#include "fic/Pipeline/Pipeline.hpp"
#include "fic/Signer/SignerClient.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>

static const std::string UX_SOCKET_FILE = "/tmp/fic_file_signer.sock";
static constexpr int RC_OK = 0;
static constexpr int RC_MODIFIED = 1;
static constexpr int RC_ERROR = 2;

using Clock = std::chrono::high_resolution_clock;
using Ms = std::chrono::milliseconds;

static long long time_ms(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration_cast<Ms>(end - start).count();
}

static void print_usage(const char *prog) {
  std::printf("usage: %s <file> [sha256|sha512|blake2b] [--timing]\n", prog);
}

static void print_hash(const Hash32 &h) {
  for (auto b : h)
    std::printf("%02x", b);
}

int main(int argc, char **argv) {
  auto t_start = Clock::now();

  if (argc < 2) {
    print_usage(argv[0]);
    return RC_ERROR;
  }

  // parse args
  const std::string file_path = argv[1];
  std::string algo_str = "sha256";
  bool show_timing = false;

  for (int i = 2; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--timing")
      show_timing = true;
    else
      algo_str = arg;
  }

  // pick engine
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

  // timing checkpoints
  Clock::time_point t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;

  // timing printer — captures all checkpoints
  auto print_timing = [&]() {
    if (!show_timing)
      return;
    std::printf("\n--- timing ---\n");
    std::printf("pipeline:      %4lldms\n", time_ms(t0, t1));
    std::printf("hash collect:  %4lldms\n", time_ms(t2, t3));
    std::printf("merkle build:  %4lldms\n", time_ms(t4, t5));
    std::printf("manifest read: %4lldms\n", time_ms(t6, t7));
    std::printf("manifest write:%4lldms\n", time_ms(t8, t9));
    std::printf("total:         %4lldms\n", time_ms(t_start, Clock::now()));
  };

  // run pipeline
  std::printf("hashing: %s\n", file_path.c_str());
  t0 = Clock::now();
  auto pipeline_result = run_pipeline(file_path.c_str(), *engine);
  t1 = Clock::now();

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
    t2 = t3 = t4 = t5 = t6 = t7 = t8 = t9 = Clock::now();
    print_timing();
    return RC_ERROR;
  }

  // collect chunk hashes
  t2 = Clock::now();
  std::vector<Hash32> hashes;
  hashes.reserve(pipeline_result.chunks.size());
  for (auto &c : pipeline_result.chunks)
    hashes.push_back(c.hash);
  t3 = Clock::now();

  // build merkle tree
  t4 = Clock::now();
  auto new_tree = MerkelTree::build(hashes, *engine);
  t5 = Clock::now();

  // read existing manifest
  t6 = Clock::now();
  auto old_manifest = read_manifest(manifest_path);
  t7 = Clock::now();

  if (!old_manifest) {
    // first run
    std::printf("no manifest found — first run\n");

    auto manifest = generate_manifest(file_path, pipeline_result.chunks,
                                      new_tree.root(), algo);
    auto msg = build_signing_message(manifest.header);
    try {
      auto sig = request_signature_from_host(msg, UX_SOCKET_FILE);
      manifest.signature = sig;
    } catch (const std::exception &e) {
      std::printf("error: signing failed: %s\n", e.what());
      return RC_ERROR;
    }

    t8 = Clock::now();
    if (!write_manifest(manifest, manifest_path)) {
      std::printf("error: could not write manifest\n");
      t9 = Clock::now();
      print_timing();
      return RC_ERROR;
    }
    t9 = Clock::now();

    std::printf("chunks:   %zu\n", pipeline_result.chunks.size());
    std::printf("root:     ");
    print_hash(new_tree.root());
    std::printf("\n");
    std::printf("manifest: %s\n", manifest_path.c_str());
    std::printf("status:   OK\n");

    print_timing();
    return RC_OK;

  } else {
    // incremental run — rebuild old tree from manifest
    std::vector<Hash32> old_hashes;
    old_hashes.reserve(old_manifest->chunks.size());
    for (auto &c : old_manifest->chunks)
      old_hashes.push_back(c.hash);

    auto old_tree = MerkelTree::build(old_hashes, *engine);
    auto old_msg = build_signing_message(old_manifest->header);

    if (verify_signature(old_msg, old_manifest->signature) &&
        MerkelTree::verify(old_tree, new_tree)) {
      // file unchanged
      std::printf("status:   OK — file unchanged\n");
      std::printf("root:     ");
      print_hash(new_tree.root());
      std::printf("\n");

      t8 = t9 = Clock::now();
      print_timing();
      return RC_OK;
    } else {
      // file modified — find exactly what changed
      auto diffs = MerkelTree::diff(old_tree, new_tree);

      std::printf("status:   MODIFIED\n");
      std::printf("changed:  %zu chunk(s)\n", diffs.size());
      std::printf("\n");

      for (auto &d : diffs) {
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

      // update manifest
      auto new_manifest = generate_manifest(file_path, pipeline_result.chunks,
                                            new_tree.root(), algo);

      t8 = Clock::now();
      if (!write_manifest(new_manifest, manifest_path)) {
        std::printf("error: could not write manifest\n");
        t9 = Clock::now();
        print_timing();
        return RC_ERROR;
      }
      t9 = Clock::now();

      print_timing();
      return RC_MODIFIED;
    }
  }
}
