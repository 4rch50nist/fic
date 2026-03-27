cmake_minimum_required(VERSION 3.20)
project(FileIntegrityChecker LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
# ---- targets ----
add_executable(fic
    main.cpp
    fic/Manifest/Manifest.cpp
    fic/Signer/SignerClient.cpp
)
add_executable(fic-signer
    fic/Signer/SignerServer.cpp
)
add_executable(fic-keygen
    fic/Key/KeyGenerator.cpp
)
# ---- common setup ----
foreach(target fic fic-signer fic-keygen)
    target_include_directories(${target} PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${SODIUM_INCLUDE_DIRS}
    )
    target_compile_options(${target} PRIVATE
        ${SODIUM_CFLAGS}
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion
    )
    target_link_options(${target} PRIVATE ${SODIUM_LDFLAGS}) 
    target_link_libraries(${target} PRIVATE ${SODIUM_LIBRARIES})
endforeach()
# ---- fic only ----
target_link_libraries(fic PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)
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
