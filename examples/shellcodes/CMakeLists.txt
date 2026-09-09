cmake_minimum_required(VERSION 3.22)

include(FetchContent)

# CMakePresets.json points at SCFW's initially missing toolchain,
# loaded only by project(). Populating here makes that path valid.
# SOURCE_SUBDIR defers SCFW's own configuration.
FetchContent_Declare(
    scfw
    GIT_REPOSITORY https://github.com/vmi-rs/scfw.git
    GIT_TAG master
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR cmake
)
FetchContent_MakeAvailable(scfw)

# Language detection now runs through SCFW's Windows cross-compilation toolchain.
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

# Keep the dependency minimal.
set(SCFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SCFW_BUILD_TOOLS OFF CACHE BOOL "" FORCE)

# Injected payloads must free their memory.
set(SCFW_OPT_CLEANUP ON CACHE BOOL "" FORCE)

# Include and configure SCFW now that its options are fixed.
add_subdirectory("${scfw_SOURCE_DIR}" "${scfw_BINARY_DIR}")

# Once vmi-utils publishes shellcode/, uncomment this block and remove the local
# add_subdirectory below. Pin URL_HASH to the checksum in the crates.io index.
# FetchContent_Declare(
#     vmi_utils
#     URL https://static.crates.io/crates/vmi-utils/vmi-utils-0.11.0.crate
#     SOURCE_SUBDIR shellcode
# )
# FetchContent_MakeAvailable(vmi_utils)

# Keep the guest packet layout and register transport in lockstep with the
# Rust bridge implementation that decodes them.
add_subdirectory(
    "${CMAKE_CURRENT_LIST_DIR}/../../crates/vmi-utils/shellcode"
    "${CMAKE_CURRENT_BINARY_DIR}/vmi-utils-shellcode"
)

# Finally, add the shellcode subdirectories.
add_subdirectory(deploy)
add_subdirectory(file-transfer)
add_subdirectory(msgbox)
