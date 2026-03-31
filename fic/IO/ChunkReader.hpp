#pragma once
#include <memory>

/// A file is broken into Chunks of size CHUNK_SIZE to stream into
/// a queue of workers ready to digest this and spit out hashes.
/// A larger chunk size is implies more read time and slightly higher wait time
/// for the workers (with less idle time incase the reader cannot keep up)
constexpr size_t CHUNK_SIZE = (1 << 23);

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
    Chunk(const uint64_t id,const uint64_t off,const size_t sz,std::unique_ptr<uint8_t[]> d)
        : chunk_id{id}, offset{off}, size{sz}, data{std::move(d)}, hash{} {}

    void release_data();
};

/// Ok -> We finished fine
/// ErrorOpen -> Error while opening file
/// ErrorLock -> Error while acquiring lock for file
/// ErrorRead -> Error while trying to read file
/// Aborted -> We could not complete the task because of a non IO-error that
/// is outside the purview of the streamer.
enum class StreamResult { Ok, ErrorOpen, ErrorLock, ErrorRead, Aborted };


template <typename F>
StreamResult stream_chunk(const char *, F &&);