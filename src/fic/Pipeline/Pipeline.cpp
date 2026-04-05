#include "include/fic/Pipeline/Pipeline.hpp"
#include "include/fic/Pipeline/ThreadSafeQueue.hpp"
#include <thread>

PipelineResult run_pipeline(const char *path, const IHashEngine &engine,
                            size_t num_workers) {
  if (!num_workers)
    num_workers = 4;

  ThreadSafeQueue<Chunk> queue(128);
  FileGuard fg{};
  fg.bind(path);
  fseek(fg.get(), 0, SEEK_END);
  size_t size = static_cast<size_t>(ftell(fg.get()));
  std::vector<Chunk> results((size / CHUNK_SIZE) + 1);

  std::vector<std::thread> workers;
  workers.reserve(num_workers);

  for (size_t i = 0; i < num_workers; i++) {
    workers.emplace_back([&]() {
      while (true) {
        auto item = queue.pop();
        if (!item)
          break;

        engine.hash(item->data.get(), item->size, item->hash);
        item->release_data();
        results[item->chunk_id] = std::move(*item);
      }
    });
  }

  const StreamResult status = stream_chunk(path, [&](Chunk &&c) -> bool {
    queue.push(std::move(c));
    return true;
  });
  queue.close();
  for (auto &w : workers)
    w.join();

  return PipelineResult{status, std::move(results)};
}
