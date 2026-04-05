#pragma once
#include "include/fic/IO/FileGuard.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <memory>

/**
 * @brief Size of each chunk read from a file during streaming, in bytes.
 *
 * 8 MB per chunk balances read throughput against worker latency. Larger
 * values reduce reader idle time at the cost of higher per-chunk wait time
 * for hashing workers. Smaller values increase queue pressure and context
 * switching overhead.
 */
constexpr size_t CHUNK_SIZE = (1 << 23);

/**
 * @brief A contiguous region of a file, ready for hashing by a worker thread.
 *
 * Chunks are produced by the reader thread and consumed by worker threads
 * via a lock-free queue. Ownership of the data buffer is transferred — never
 * shared — so Chunk is move-only. Once a worker has computed the hash, the
 * buffer should be released via release_data() to reclaim memory before the
 * Chunk is forwarded to the Merkle tree builder.
 *
 * @note All chunks except the last will have size == CHUNK_SIZE. The final
 *       chunk carries whatever bytes remain and may be smaller.
 */
struct Chunk {
  uint64_t chunk_id; /// Zero-based index of this chunk within the file.
  uint64_t offset;   /// Byte offset of this chunk's first byte within the file.
  size_t size;       /// Number of valid bytes in data. Equal to CHUNK_SIZE for
                     /// all chunks except possibly the last.

  /**
   * @brief Owning buffer containing the raw file bytes for this chunk.
   *
   * Allocated by the reader thread and moved into the worker thread via the
   * queue. Must not be accessed after release_data() is called.
   */
  std::unique_ptr<uint8_t[]> data;

  /**
   * @brief 32-byte hash of this chunk's content.
   *
   * Zero-initialised on construction. Populated by the worker thread after
   * hashing data[0..size). Valid only after the worker has finished.
   */
  std::array<uint8_t, 32> hash;

  Chunk(Chunk &&) = default;
  Chunk &operator=(Chunk &&) = default;
  Chunk(const Chunk &) = delete;
  Chunk &operator=(const Chunk &) = delete;

  Chunk() : chunk_id{}, offset{}, size{}, data{}, hash{} {}

  /**
   * @brief Construct a Chunk with its buffer and positional metadata.
   *
   * @param id   Zero-based chunk index within the file.
   * @param off  Byte offset of this chunk within the file.
   * @param sz   Number of valid bytes in @p d.
   * @param d    Owning buffer of at least @p sz bytes. Ownership is
   * transferred.
   */
  Chunk(const uint64_t id, const uint64_t off, const size_t sz,
        std::unique_ptr<uint8_t[]> d)
      : chunk_id{id}, offset{off}, size{sz}, data{std::move(d)}, hash{} {}

  /**
   * @brief Release the data buffer after hashing is complete.
   *
   * Frees the raw file bytes so memory can be reclaimed before the Chunk
   * is forwarded downstream. Accessing data after this call is undefined.
   */
  void release_data();
};

/**
 * @brief Result of a stream_chunk() operation.
 */
enum class StreamResult {
  Ok, ///< All chunks were streamed and on_chunk() returned true for each.
  ErrorOpen, ///< The file could not be opened.
  ErrorLock, ///< A file lock could not be acquired.
  ErrorRead, ///< An I/O error occurred during reading.
  Aborted, ///< on_chunk() returned false — caller requested early termination.
};

/**
 * @brief Stream a file as a sequence of fixed-size chunks, invoking a callback
 *        for each.
 *
 * Opens the file at @p path, reads it sequentially in CHUNK_SIZE blocks, and
 * calls @p on_chunk(Chunk &&) for each block. On macOS, F_RDAHEAD is enabled
 * to hint the kernel to prefetch pages ahead of the read cursor.
 *
 * The callback receives ownership of the Chunk's data buffer. It must return
 * true to continue streaming or false to abort early, in which case
 * StreamResult::Aborted is returned. The callback is responsible for consuming
 * or discarding the buffer before returning.
 *
 * Streaming stops naturally at EOF or immediately on any I/O error or false
 * return from @p on_chunk.
 *
 * @tparam F    Callable type satisfying: bool F(Chunk &&).
 * @param path      Null-terminated path to the file to stream.
 * @param on_chunk  Callback invoked once per chunk in order of ascending
 * offset.
 * @return          StreamResult indicating how the operation concluded.
 *
 * @throws Nothing — all errors are communicated via StreamResult.
 */
template <typename F>
StreamResult stream_chunk(const char *path, F &&on_chunk) {
  FileGuard fg{};
  try {
    fg.bind(path);
  } catch (std::runtime_error &) {
    return StreamResult::ErrorOpen;
  }

  uint64_t chunk_id{0};
  uint64_t offset{0};

#ifdef __APPLE__
  fcntl(fileno(fg.get()), F_RDAHEAD, 1);
#endif

  while (true) {
    auto buf = std::make_unique<uint8_t[]>(CHUNK_SIZE);
    size_t bytes_read = std::fread(buf.get(), 1, CHUNK_SIZE, fg.get());

    if (bytes_read > 0) {
      if (!on_chunk(Chunk{chunk_id, offset, bytes_read, std::move(buf)}))
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
