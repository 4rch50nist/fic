cmake_minimum_required(VERSION 3.20)
project(FileIntegrityChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)     


find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)


add_executable(fic
    main.cpp
    fic/Manifest/Manifest.cpp
    fic/Signer/SignerClient.cpp
)
add_executable(fic-signer
  fic/Signer/SignerServer.cpp
)

target_link_libraries(fic-signer PRIVATE sodium)

target_include_directories(fic PRIVATE
    ${CMAKE_SOURCE_DIR}
  ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(fic PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
 ${SODIUM_LIBRARIES}
)

target_compile_options(fic PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
)
