#include "include/fic/Pipeline/Pipeline.hpp"
#include <thread>

PipelineResult run_pipeline(const char *path, const IHashEngine &engine,
                            size_t num_workers) {
  if (!num_workers)
    num_workers = 4;

  int fd = open(path, O_RDONLY);
  size_t size = static_cast<size_t>(lseek(fd, 0, SEEK_END));
  close(fd);

  size_t num_chunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;
  std::vector<Chunk> results(num_chunks);
  std::atomic<size_t> next_chunk{0};
  std::vector<std::thread> workers;
  workers.reserve(num_workers);

  for (size_t i = 0; i < num_workers; i++) {
    workers.emplace_back([&]() {
      int fd = open(path, O_RDONLY);
#ifdef __APPLE__
      fcntl(fd, F_RDAHEAD, 1);
#endif

      while (true) {
        size_t chunk_id = next_chunk.fetch_add(1);
        if (chunk_id >= num_chunks)
          break;

        size_t offset = chunk_id * CHUNK_SIZE;
        size_t to_read = std::min(CHUNK_SIZE, size - offset);

        auto buf = std::make_unique<uint8_t[]>(to_read);
        pread(fd, buf.get(), to_read, static_cast<long long>(offset));

        engine.hash(buf.get(), to_read, results[chunk_id].hash);
        results[chunk_id].chunk_id = chunk_id;
        results[chunk_id].offset = offset;
        results[chunk_id].size = to_read;
      }
      close(fd);
    });
  }

  for (auto &w : workers)
    w.join();

  return PipelineResult{StreamResult::Ok, std::move(results)};
}
