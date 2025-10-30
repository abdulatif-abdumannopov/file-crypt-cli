cmake_minimum_required(VERSION 3.10)
project(crypto_tool C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (WIN32)
    add_executable(crypto_tool main.c getopt.c)
else()
    add_executable(crypto_tool main.c)
endif()

target_link_libraries(crypto_tool OpenSSL::Crypto)


