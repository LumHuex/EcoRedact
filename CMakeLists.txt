cmake_minimum_required(VERSION 3.10)
project(EcoRedact)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)

# 头文件目录
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${OPENSSL_INCLUDE_DIR})

# 源文件
set(SOURCES
    src/ecoreact.cpp
    src/blockchain.cpp
    src/main.cpp
)

# 可执行文件
add_executable(ecoreact ${SOURCES})

# 链接 OpenSSL 库
target_link_libraries(ecoreact ${OPENSSL_LIBRARIES} crypto ssl)

# 编译选项
target_compile_options(ecoreact PRIVATE -O3 -Wall -Wno-deprecated-declarations)