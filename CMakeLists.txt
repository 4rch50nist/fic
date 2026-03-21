cmake_minimum_required(VERSION 3.20)
project(FileIntegrityChecker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)     


find_package(OpenSSL REQUIRED)


add_executable(fic
    main.cpp
    fic/Manifest/Manifest.cpp
)


target_include_directories(fic PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(fic PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_options(fic PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
)
