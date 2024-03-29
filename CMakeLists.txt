cmake_minimum_required (VERSION 3.12)
project (BBPTT C)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

###############################################################################
# Set build features
set(CMAKE_BUILD_TYPE Debug)

set (DATABASE "ouilookup.db")
# Check to see if SQLite3 is installed
find_package(SQLite3 REQUIRED)
include_directories(${SQLITE3_INCLUDE_DIRS})
link_directories(${SQLITE3_LIBRARIES})

###############################################################################
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

###############################################################################
# Check headers
set(INCLUDES "")
macro(ck_check_include_file header var)
  check_include_files("${INCLUDES};${header}" ${var})
  if(${var})
    set(INCLUDES ${INCLUDES} ${header})
  endif(${var})
endmacro(ck_check_include_file)

ck_check_include_file("stdlib.h" HAVE_STDLIB_H)

###############################################################################
# Check functions

###############################################################################
# Check defines

###############################################################################
# Check struct members

###############################################################################
# Check for integer types
# (The following are used in check.h. Regardless if they are used in
# the project, they will need to be checked in order to use Check).
check_type_size(intmax_t INTMAX_T)
check_type_size(uintmax_t UINTMAX_T)

check_type_size(pid_t PID_T)
if(NOT HAVE_PID_T)
  if(WIN32)
    set(pid_t "int")
  else(WIN32)
    MESSAGE(FATAL_ERROR "pid_t doesn't exist on this platform?")
  endif(WIN32)
endif(NOT HAVE_PID_T)

###############################################################################
# Check libraries

###############################################################################
# Generate "config.h" from "cmake/config.h.cmake"
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})
add_definitions(-DHAVE_CONFIG_H)
set(CONFIG_HEADER ${CMAKE_CURRENT_BINARY_DIR}/config.h)

###############################################################################
# Subdirectories
add_subdirectory(tests)

###############################################################################
# Unit tests
enable_testing()
add_test(NAME check_bbptt COMMAND check_bbptt)

set (CMAKE_BINARY_DIR ${BBPTT_SOURCE_DIR}/bin)
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})



set(LIB_SOURCES
${BBPTT_SOURCE_DIR}/src/logger.c
${BBPTT_SOURCE_DIR}/src/bluetooth.c
${BBPTT_SOURCE_DIR}/src/utils.c
${BBPTT_SOURCE_DIR}/src/database.c
)

set(MAIN_SOURCES
${BBPTT_SOURCE_DIR}/src/main.c
)

set(HEADERS 
  ${CONFIG_HEADER}
  ${BBPTT_SOURCE_DIR}/src/logger.h
  ${BBPTT_SOURCE_DIR}/src/bluetooth.h
  ${BBPTT_SOURCE_DIR}/src/utils.h
  ${BBPTT_SOURCE_DIR}/src/database.h
)

add_library(bbptt STATIC ${LIB_SOURCES} ${HEADERS})

add_executable(bluebornepentest ${HEADERS} ${MAIN_SOURCES})
target_link_libraries(bluebornepentest bbptt bluetooth ${SQLITE3_LIBRARIES})

install(TARGETS bbptt
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)

add_custom_command(TARGET bbptt POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy
                      ${CMAKE_SOURCE_DIR}/res/${DATABASE} ${CMAKE_BINARY_DIR})
