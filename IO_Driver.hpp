#pragma once
#include "FileGuard.hpp"
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>

constexpr size_t CHUNK_SIZE = 1 * 1024 * 1024;

struct Chunk {
  uint64_t chunk_id;
  uint64_t offset;
  size_t size;
  std::unique_ptr<uint8_t[]> data;

  Chunk(Chunk &&) = default;
  Chunk &operator=(Chunk &&) = default;

  Chunk(const Chunk &) = delete;
  Chunk &operator=(const Chunk &) = delete;
  Chunk(uint64_t id, uint64_t off, size_t sz, std::unique_ptr<uint8_t[]> d)
      : chunk_id{id}, offset{off}, size{sz}, data{std::move(d)} {}
};

using ChunkCallback = std::function<bool(Chunk &&)>;

enum class StreamResult { Ok, ErrorOpen, ErrorLock, ErrorRead, Aborted };

inline StreamResult stream_chunk(const char *path, ChunkCallback on_chunk) {
  FileGuard fg{};
  try {
    fg.bind(path);
  } catch (std::runtime_error &) {
    return StreamResult::ErrorOpen;
  }

  uint64_t chunk_id{0};
  uint64_t offset{0};

  while (true) {
    auto buf = std::make_unique<uint8_t[]>(CHUNK_SIZE);
    size_t bytes_read = std::fread(buf.get(), 1, CHUNK_SIZE, fg.get());

    if (bytes_read > 0) {
      Chunk chunk{chunk_id, offset, bytes_read, std::move(buf)};

      if (!on_chunk(std::move(chunk)))
        return StreamResult::Aborted;

      chunk_id++;
      offset += bytes_read;
    }

    if (bytes_read < CHUNK_SIZE) {
      if (std::ferror(fg.get()))
        return StreamResult::ErrorRead;
      break;
    }
  }

  return StreamResult::Ok;
}
