cmake_minimum_required(VERSION 2.8)
project(gloriousocks)

set(CMAKE_CXX_STANDARD 11)

# libev setting
set(LIBEV_DIR ${CMAKE_SOURCE_DIR}/thirdparty/libev)
include_directories(${LIBEV_DIR}/include)
link_directories(${LIBEV_DIR}/lib)

file(GLOB SRC
        ${CMAKE_SOURCE_DIR}/src/*.cpp
        ${CMAKE_SOURCE_DIR}/src/*.hpp)

add_executable(gloriousocks ${SRC})
target_link_libraries(gloriousocks ev)
