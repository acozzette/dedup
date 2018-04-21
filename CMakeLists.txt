project(dedup)
cmake_minimum_required(VERSION 3.5)
set(D_FILE_OFFSET_BITS 64)

add_subdirectory(BUSE)

add_executable(dedup dedup.c)
target_link_libraries(dedup buse crypto pthread zlog)