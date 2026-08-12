cmake_minimum_required(VERSION 3.22)
project(deto-injector-shellcode C CXX ASM)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "This project requires Clang")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SCFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SCFW_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(SCFW_OPT_CLEANUP ON CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../../../scfw ${CMAKE_CURRENT_BINARY_DIR}/scfw)
add_subdirectory(bridge)
add_subdirectory(shellcodes)
