cmake_minimum_required(VERSION 3.10)

# Project name
project(stmulator)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)

# Set the source directory
set(SRC_DIR "${CMAKE_SOURCE_DIR}/src")

# Recursively find all .cpp files in src/ and its subdirectories
file(GLOB_RECURSE SRC_FILES "${SRC_DIR}/*.cpp")

# Set the build type
set(CMAKE_BUILD_TYPE Debug)

# Set the path to the Capstone source directory
set(CAPSTONE_DIR "${CMAKE_SOURCE_DIR}/capstone")

# Ensure the Capstone source directory exists
if (NOT EXISTS "${CAPSTONE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "Capstone directory not found at ${CAPSTONE_DIR}")
endif()

# Specify an out-of-tree build directory for Capstone
set(CAPSTONE_BUILD_DIR "${CMAKE_BINARY_DIR}/capstone_build")

# Add the source directory to the list of include paths
include_directories(${SRC_DIR})
# Recursively add all subdirectories in SRC_DIR to the include paths
file(GLOB INCLUDE_DIRS RELATIVE ${SRC_DIR} ${SRC_DIR}/*)
foreach(dir ${INCLUDE_DIRS})
    if(IS_DIRECTORY ${SRC_DIR}/${dir})
        include_directories(${SRC_DIR}/${dir})
    endif()
endforeach()

# Add executable target from the source files
add_executable(${PROJECT_NAME} ${SRC_FILES})

# Add the Capstone project with out-of-tree build
add_subdirectory("${CAPSTONE_DIR}" "${CAPSTONE_BUILD_DIR}")

# Link Capstone to your target
target_link_libraries(${PROJECT_NAME} PRIVATE capstone)
