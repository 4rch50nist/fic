cmake_minimum_required(VERSION 3.20)
project(FileIntegrityChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMAND ON)

# ---- dependencies ----
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# ---- core library ----
file(GLOB_RECURSE CORE_SRC CONFIGURE_DEPENDS
    src/fic/*.cpp
)

add_library(core ${CORE_SRC})

target_include_directories(core PUBLIC
    ${CMAKE_SOURCE_DIR}
)

target_compile_options(core PRIVATE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion
)

target_link_libraries(core PUBLIC
    OpenSSL::Crypto
    PkgConfig::SODIUM
)

# ---- Apple Keychain ----
if(APPLE)
    find_library(SECURITY_FRAMEWORK Security REQUIRED)
    find_library(COREFOUNDATION_FRAMEWORK CoreFoundation REQUIRED)

    target_sources(core PRIVATE
        src/fic/Key/Providers/KeyChainProvider.cpp
    )

    target_link_libraries(core PRIVATE
        ${SECURITY_FRAMEWORK}
        ${COREFOUNDATION_FRAMEWORK}
    )

    target_compile_definitions(core PUBLIC FIC_USE_KEYCHAIN)
endif()

# ---- executables ----
add_executable(fic main.cpp)
target_link_libraries(fic PRIVATE core OpenSSL::SSL)

add_executable(fic-signer src/fic/Signer/SignerServer.cpp)
target_link_libraries(fic-signer PRIVATE core)

add_executable(fic-keygen src/fic/Key/KeyGenerator.cpp)
target_link_libraries(fic-keygen PRIVATE core)
