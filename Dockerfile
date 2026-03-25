# --- build stage ---
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libssl-dev \
    libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build

# --- runtime stage ---
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    libsodium23 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/build/fic .

ENTRYPOINT ["./fic"]
