#include "include/fic/IO/ChunkReader.hpp"

#include <fcntl.h>
#include <memory>

void Chunk::release_data() { data.release(); }
