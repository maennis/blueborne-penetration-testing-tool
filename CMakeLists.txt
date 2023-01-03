cmake_minimum_required (VERSION 3.12)
project (BBPTT)

set (CMAKE_BINARY_DIR ${BBPTT_SOURCE_DIR}/bin)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable (bluebornepentest src/main.c)
