cmake_minimum_required (VERSION 2.6)
project (cryptopals)

SET (CMAKE_CXX_COMPILER "/usr/bin/clang++")
SET (CMAKE_CXX_FLAGS "-std=c++1z -g -Weverything \
-Wno-c++98-compat -Wno-c++98-compat-pedantic \
-Wno-conversion -Wno-sign-conversion \
-Wno-missing-prototypes -Wno-exit-time-destructors \
-fsanitize=address -fno-omit-frame-pointer")
# --analyze -Qunused-arguments")

add_library(utilities utilities.cpp)
add_executable(main main.cpp)
target_link_libraries(main utilities)
