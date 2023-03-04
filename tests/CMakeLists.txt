include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

find_package(Check REQUIRED)
include_directories(${CHECK_INCLUDE_DIRS})
link_directories(${CHECK_LIBRARY_DIRS})

set(TEST_SOURCES
  check_bbptt.c
)

add_executable(check_bbptt ${TEST_SOURCES})
target_link_libraries(check_bbptt bbptt ${CHECK_LIBRARIES} ${SQLITE3_LIBRARIES} bluetooth)
target_link_libraries(check_bbptt m pthread check_pic rt subunit)

add_custom_command(TARGET check_bbptt POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy
                      ${CMAKE_CURRENT_SOURCE_DIR}/../res/${DATABASE} ${CMAKE_CURRENT_SOURCE_DIR}/res)
