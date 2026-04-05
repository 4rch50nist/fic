#pragma once
#include "include/fic/Engines/IHashEngine.hpp"
#include "include/fic/IO/ChunkReader.hpp"
#include <thread>
#include <vector>

struct PipelineResult {
  StreamResult streamResult;
  std::vector<Chunk> chunks;

  PipelineResult(const StreamResult &streamResult, std::vector<Chunk> &&chunks)
      : streamResult{streamResult}, chunks{std::move(chunks)} {}
};

PipelineResult
run_pipeline(const char *, const IHashEngine &,
             size_t num_workers = std::thread::hardware_concurrency());
