#pragma once
#include "FileGuard.hpp"
#include "ChunkReader.hpp"
#include <cstdint>
#include <cstdio>
#include <memory>



void Chunk::release_data(){
  data.release();
}
/// streams a vector of chunks from the file given in path.
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
