cmake_minimum_required(VERSION 3.20)
project(FileIntegrityChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ---- fic (client) ----
add_executable(fic
    main.cpp
    fic/Manifest/Manifest.cpp
    fic/Signer/SignerClient.cpp
)

# ---- signer (host) ----
add_executable(fic-signer
    fic/Signer/SignerServer.cpp
)

# ---- keygen (host) ----
add_executable(fic-keygen
    fic/Key/KeyGenerator.cpp
)

# ---- common include dirs ----
foreach(target fic fic-signer fic-keygen)
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${SODIUM_INCLUDE_DIRS}
    )

    # 🔥 THIS IS WHAT YOU WERE MISSING
    target_compile_options(${target} PRIVATE ${SODIUM_CFLAGS})
    target_link_options(${target} PRIVATE ${SODIUM_LDFLAGS})

    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion
    )
endforeach()

# ---- linking ----
target_link_libraries(fic PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SODIUM_LIBRARIES}
)

target_link_libraries(fic-signer PRIVATE
    ${SODIUM_LIBRARIES}
)

target_link_libraries(fic-keygen PRIVATE
    ${SODIUM_LIBRARIES}
)
