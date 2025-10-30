cmake_minimum_required(VERSION 3.10)
project(file_crypt_cli C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (WIN32)
    add_executable(file_crypt_cli main.c getopt.c)
else()
    add_executable(file_crypt_cli main.c)
endif()

target_link_libraries(file_crypt_cli OpenSSL::Crypto)
