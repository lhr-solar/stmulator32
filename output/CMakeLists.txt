cmake_minimum_required(VERSION 3.10)

# Project name
project(stmulator)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)

# Set the source directory
set(SRC_DIR "../src")

# Recursively find all .cpp files in src/ and its subdirectories
file(GLOB_RECURSE SRC_FILES "${SRC_DIR}/*.cpp")

set(CMAKE_BUILD_TYPE Debug)

find_library(caplib "../libcapstone.so")

# Add executable target from the source files
add_executable(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE "${caplib}")