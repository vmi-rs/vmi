add_library(bridge STATIC src/arch/x64/bridge.S)

target_include_directories(bridge PUBLIC include)
target_compile_options(bridge PRIVATE --target=${CMAKE_ASM_COMPILER_TARGET})

add_library(enum_flags_test OBJECT tests/enum_flags.cpp)
target_include_directories(enum_flags_test PRIVATE include)
