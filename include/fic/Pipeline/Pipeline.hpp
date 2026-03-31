#pragma once
#include <vector>
#include "include/fic/IO/ChunkReader.hpp"
#include "IHashEngine.hpp"
#include <thread>

struct PipelineResult
{
    StreamResult streamResult;
    std::vector<Chunk> chunks;

    PipelineResult(const StreamResult &streamResult, std::vector<Chunk> &chunks): streamResult{streamResult}, chunks{std::move(chunks)} { }
};

PipelineResult
run_pipeline(const char *, const IHashEngine &,
             size_t num_workers = std::thread::hardware_concurrency());


