cmake_minimum_required(VERSION 3.22)

include(FetchContent)

FetchContent_Declare(
    scfw
    GIT_REPOSITORY https://github.com/vmi-rs/scfw.git
    GIT_TAG master
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR cmake
)
FetchContent_MakeAvailable(scfw)

project(windows_bridge_shellcode C CXX ASM)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "This project requires Clang")
endif()

if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    message(FATAL_ERROR "This project supports x64 only")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SCFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SCFW_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(SCFW_OPT_CLEANUP ON CACHE BOOL "" FORCE)

add_subdirectory("${scfw_SOURCE_DIR}" "${scfw_BINARY_DIR}")
add_subdirectory(proto)
add_subdirectory(shellcodes)
