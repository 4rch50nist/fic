#pragma once
#include "../../IHashEngine.hpp"
#include "../IO/ChunkReader.hpp"
#include "ThreadSafe.hpp"
#include <algorithm>
#include <thread>

struct PipelineResult {
  StreamResult streamResult;
  std::vector<Chunk> chunks;
};

inline PipelineResult
run_pipeline(const char *path, const IHashEngine &engine,
             size_t num_workers = (size_t)std::thread::hardware_concurrency()) {
  if (!num_workers)
    num_workers = 4;

  ThreadSafeQueue<Chunk> queue(64);
  std::vector<std::vector<Chunk>> per_worker_results(num_workers);

  std::vector<std::thread> workers;
  workers.reserve(num_workers);

  for (size_t i = 0; i < num_workers; i++) {
    workers.emplace_back([&, i]() {
      auto &local = per_worker_results[i];
      while (true) {
        auto item = queue.pop();
        if (!item)
          break;

        engine.hash(item->data.get(), item->size, item->hash);
        item->release_data();
        local.push_back(std::move(*item));
      }
    });
  }

  StreamResult status = stream_chunk(path, [&](Chunk &&c) -> bool {
    queue.push(std::move(c));
    return true;
  });
  queue.close();
  for (auto &w : workers)
    w.join();

  std::vector<Chunk> results;
  results.reserve([&] {
    size_t n = 0;
    for (auto &v : per_worker_results)
      n += v.size();
    return n;
  }());
  for (auto &v : per_worker_results)
    for (auto &c : v)
      results.push_back(std::move(c));

  std::sort(results.begin(), results.end(), [](const Chunk &a, const Chunk &b) {
    return a.chunk_id < b.chunk_id;
  });

  return PipelineResult{.streamResult = status, .chunks = std::move(results)};
}
