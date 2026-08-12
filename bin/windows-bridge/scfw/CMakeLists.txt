cmake_minimum_required(VERSION 3.22)
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

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../scfw ${CMAKE_CURRENT_BINARY_DIR}/scfw)
add_subdirectory(proto)
add_subdirectory(shellcodes)
