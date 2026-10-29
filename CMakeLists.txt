cmake_minimum_required(VERSION 3.14)
project(Lines VERSION 1.0.0 LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(-O3 -fno-sanitize=all)
add_link_options(-fno-sanitize=all)

# --- Standard (Ksee) Dependency ---
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../standard/CMakeLists.txt")
    message(STATUS "[Lines] Using local standard from ../standard")
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../standard" "${CMAKE_CURRENT_BINARY_DIR}/standard")
else()
    message(STATUS "[Lines] Fetching standard from ksee6/standard")
    include(FetchContent)
    FetchContent_Declare(
        Standard
        GIT_REPOSITORY https://github.com/ksee6/standard.git
        GIT_TAG main
    )
    FetchContent_MakeAvailable(Standard)
endif()

# --- Automatic Source Discovery ---
file(GLOB_RECURSE LINES_SOURCES 
    "src/Lines/*.cpp"
    "src/Lines/**/*.cpp"
)

# Main Lines Library
add_library(Lines STATIC ${LINES_SOURCES})

# Include Directories
target_include_directories(Lines PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link Ksee
target_link_libraries(Lines PUBLIC Ksee::Ksee)

# Alias for consistent usage
if(NOT TARGET Lines::Lines)
    add_library(Lines::Lines ALIAS Lines)
endif()

# Tests
option(LINES_BUILD_TESTS "Build Lines tests" ON)

if(LINES_BUILD_TESTS)
    enable_testing()

    add_executable(test_lines tests/test_lines.cpp)
    target_link_libraries(test_lines PRIVATE Lines::Lines)
    set_target_properties(test_lines PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
    add_test(NAME test_lines COMMAND test_lines)

    add_executable(lines_server tests/server.cpp)
    target_link_libraries(lines_server PRIVATE Lines::Lines)
    set_target_properties(lines_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")

    add_executable(lines_client tests/client.cpp)
    target_link_libraries(lines_client PRIVATE Lines::Lines)
    set_target_properties(lines_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/tests")
endif()
