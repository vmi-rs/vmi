add_library(vmi_shellcode STATIC src/arch/x64/transport.S)
add_library(vmi::shellcode ALIAS vmi_shellcode)

target_include_directories(vmi_shellcode PUBLIC include)
target_compile_options(
    vmi_shellcode
    PRIVATE --target=${CMAKE_ASM_COMPILER_TARGET}
)
