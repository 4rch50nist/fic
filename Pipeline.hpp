#pragma once
#include "IO_Driver.hpp"
#include "ThreadSafe.hpp"
#include <algorithm>
#include <mutex>
#include <thread>

static void hash_chunk_stub(Chunk &c) {
  c.hash.fill(0);
  c.release_data();
}

struct PipelineResult {
  StreamResult streamResult;
  std::vector<Chunk> chunks;
};

inline PipelineResult
run_pipeline(const char *path,
             size_t num_workers = (size_t)std::thread::hardware_concurrency()) {
  if (!num_workers)
    num_workers = 4;

  ThreadSafeQueue<Chunk> queue(num_workers << 1);

  std::vector<Chunk> results;
  std::mutex mx;

  std::vector<std::thread> workers;
  workers.reserve(num_workers);

  for (int i = 0; i < num_workers; i++) {
    workers.emplace_back([&]() {
      while (true) {
        auto item = queue.pop();
        if (!item)
          break;

        hash_chunk_stub(*item);

        std::lock_guard lock(mx);
        results.push_back(std::move(*item));
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

  std::sort(results.begin(), results.end(),
            [](const Chunk &c1, const Chunk &c2) {
              return c1.chunk_id < c2.chunk_id;
            });

  return PipelineResult{.streamResult = status, .chunks = std::move(results)};
}
