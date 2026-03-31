cmake_minimum_required(VERSION 3.20)
project(FileIntegrityChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- dependencies ----
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# ---- core library (all project code) ----
file(GLOB_RECURSE CORE_SRC
        src/fic/*.cpp
)

add_library(core ${CORE_SRC} fic)

target_include_directories(core PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${SODIUM_INCLUDE_DIRS}
)

target_compile_options(core PRIVATE
        ${SODIUM_CFLAGS}
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion
)

target_link_libraries(core PUBLIC
        ${SODIUM_LIBRARIES}
)

target_link_options(core PRIVATE
        ${SODIUM_LDFLAGS}
)

# ---- executables ----
add_executable(fic main.cpp)
target_link_libraries(fic PRIVATE
        core
        OpenSSL::SSL
        OpenSSL::Crypto
)

add_executable(fic-signer fic/Signer/SignerServer.cpp)
target_link_libraries(fic-signer PRIVATE core)

add_executable(fic-keygen fic/Key/KeyGenerator.cpp)
target_link_libraries(fic-keygen PRIVATE core)

# ---- Apple Keychain ----
if(APPLE)
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)

    foreach(target fic fic-signer fic-keygen)
        target_sources(${target} PRIVATE
                fic/Key/Providers/KeyChainProvider.cpp
        )
        target_link_libraries(${target} PRIVATE
                ${SECURITY_FRAMEWORK}
                ${COREFOUNDATION_FRAMEWORK}
        )
        target_compile_definitions(${target} PRIVATE FIC_USE_KEYCHAIN)
    endforeach()
endif()