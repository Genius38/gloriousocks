cmake_minimum_required(VERSION 2.8)
project(gloriousocks)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# libev udns setting
set(LIBEV_DIR ${CMAKE_SOURCE_DIR}/thirdparty/libev/build)
include_directories(
        ${LIBEV_DIR}/include
)
link_directories(
        ${LIBEV_DIR}/lib
)

file(GLOB SERVER_SRC
        ${CMAKE_SOURCE_DIR}/src/server/*.cpp
        ${CMAKE_SOURCE_DIR}/src/server/*.h)

file(GLOB CLIENT_SRC
        ${CMAKE_SOURCE_DIR}/src/client/*.cpp
        ${CMAKE_SOURCE_DIR}/src/client/*.h)

add_executable(gloriousocks_server ${SERVER_SRC})
target_link_libraries(gloriousocks_server ev)

add_executable(gloriousocks_client ${CLIENT_SRC})
target_link_libraries(gloriousocks_client ev)
