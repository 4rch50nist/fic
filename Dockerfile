FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build

ENTRYPOINT ["./build/fic"]
