cmake_minimum_required(VERSION 3.28)

project(remitly_home_excercise)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -Wpedantic")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")
file(GLOB_RECURSE SOURCES "${SOURCE_DIR}/*.cpp")

include_directories(${SOURCE_DIR})

add_subdirectory(extern/json)
add_subdirectory(extern/catch2)

add_executable(remitly_home_excercise ${SOURCES})

target_link_libraries(remitly_home_excercise PRIVATE nlohmann_json::nlohmann_json Catch2::Catch2WithMain)
