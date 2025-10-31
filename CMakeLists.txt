cmake_minimum_required(VERSION 3.10)
project(file_crypt_cli C)

set(CMAKE_C_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(file_crypt_cli main.c)

target_link_libraries(file_crypt_cli PRIVATE OpenSSL::Crypto)
