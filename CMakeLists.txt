cmake_minimum_required(VERSION 3.10)
project(untitled C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(untitled main.c)

target_link_libraries(untitled OpenSSL::Crypto)
