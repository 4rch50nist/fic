#pragma once
#include <vector>
#include "fic/IO/ChunkReader.hpp"

struct PipelineResult
{
    StreamResult streamResult;
    std::vector<Chunk> chunks;

    PipelineResult(const StreamResult &streamResult, std::vector<Chunk> &chunks): streamResult{streamResult}, chunks{std::move(chunks)} { }
};

PipelineResult
run_pipeline(const char *, const IHashEngine &,
             size_t num_workers = std::thread::hardware_concurrency());


