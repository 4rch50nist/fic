#pragma once
#include "FileGuard.hpp"
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>

/// A file is broken into Chunks of size CHUNK_SIZE to stream into
/// a queue of workers ready to digest this and spit out hashes.
/// A larger chunk size is implies more read time and slightly higher wait time
/// for the workers (with less idle time incase the reader cannot keep up)
constexpr size_t CHUNK_SIZE = 8 * 1024 * 1024;

struct Chunk {
  uint64_t chunk_id;

  /// offset in the file
  uint64_t offset;

  /// size of the chunk. Except for the last one, all should follow
  /// CHUNK_SIZE
  size_t size;

  /// Data of the chunk that is kept to pass onto worker for
  /// hashing. Its a unique pointer because we want to move the Chunks from the
  /// reader-thread to the writer-thread(s)[1 -> 2...N] so we cannot allow them
  /// to copy. Instead, just move the whole thing onto some other thread and let
  /// it be its headache.
  std::unique_ptr<uint8_t[]> data;
  std::array<uint8_t, 32> hash;

  Chunk(Chunk &&) = default;
  Chunk &operator=(Chunk &&) = default;

  Chunk(const Chunk &) = delete;
  Chunk &operator=(const Chunk &) = delete;
  Chunk(uint64_t id, uint64_t off, size_t sz, std::unique_ptr<uint8_t[]> d)
      : chunk_id{id}, offset{off}, size{sz}, data{std::move(d)} {}

  void release_data() { data.reset(); }
};

/// Action to perform on each chunk. This takes in a movable
/// rvalue that the caller then gets ownership of.
using ChunkCallback = std::function<bool(Chunk &&)>;

/// Ok -> We finished fine
/// ErrorOpen -> Error while opening file
/// ErrorLock -> Error while acquiring lock for file
/// ErrorRead -> Error while trying to read file
/// Aborted -> We could not complete the task because of a non IO-error that
/// is outside the perview of the streamer.
enum class StreamResult { Ok, ErrorOpen, ErrorLock, ErrorRead, Aborted };

/// streams a vector of chunks from the file given in path.
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

      /// The streamer did call on_chunk(Chunk &&) but for some reason
      /// we encountered a state where the return is false (implying that
      /// something) that should not have happened has happened. So we must
      /// abort and let the caller know that we couldnt complete the request
      /// because something went wrong in their function.
      // printf("Read chunk:%llu\n", chunk_id);
      if (!on_chunk(std::move(chunk)))
        return StreamResult::Aborted;

      chunk_id++;
      offset += bytes_read;
    }

    if (bytes_read < CHUNK_SIZE) {

      /// Check to see if we had a bad read
      /// If not then we are at EOF so terminate the loop.
      if (std::ferror(fg.get()))
        return StreamResult::ErrorRead;
      break;
    }
  }

  return StreamResult::Ok;
}
