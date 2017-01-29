cmake_minimum_required (VERSION 2.6)
project (cryptopals)

SET (CMAKE_CXX_COMPILER             "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS                "-std=c++1z -Wall -Wextra")

add_library(utilities utilities.cpp)
add_executable(main main.cpp)
target_link_libraries(main utilities)
