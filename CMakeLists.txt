cmake_minimum_required(VERSION 3.10)
project(EcoRedact)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SOURCES
    src/ecoreact.cpp
    src/blockchain.cpp
    src/main.cpp
)

add_executable(ecoreact ${SOURCES})
target_link_libraries(ecoreact ${OPENSSL_LIBRARIES} crypto ssl)
target_compile_options(ecoreact PRIVATE -O3 -Wall -Wno-deprecated-declarations)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/keys)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/keys/blockchain)
