cmake_minimum_required (VERSION 2.6)
project (cryptopals)

SET (CMAKE_CXX_COMPILER "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS "-std=c++1z -g -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-missing-prototypes -Wno-sign-conversion -Wno-conversion -Wno-exit-time-destructors -fsanitize=address -fno-omit-frame-pointer ")

add_library(utilities utilities.cpp)
add_executable(main main.cpp)
target_link_libraries(main utilities)
