add_library(bridge STATIC src/arch/x64/transport.S)

target_include_directories(bridge PUBLIC include)
target_compile_options(bridge PRIVATE --target=${CMAKE_ASM_COMPILER_TARGET})

