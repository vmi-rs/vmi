# Guest-side support for shellcodes used with vmi-utils.

# The transport makes the bridge call, with BRK on AArch64 and with VMCALL or
# CPUID on x64.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    set(VMI_SHELLCODE_TRANSPORT src/arch/arm64/transport.S)
else()
    set(VMI_SHELLCODE_TRANSPORT src/arch/x64/transport.S)
endif()

add_library(vmi_shellcode STATIC ${VMI_SHELLCODE_TRANSPORT})
add_library(vmi::shellcode ALIAS vmi_shellcode)

target_include_directories(vmi_shellcode PUBLIC include)
target_compile_options(
    vmi_shellcode
    PRIVATE --target=${CMAKE_ASM_COMPILER_TARGET}
)

# Extracts the shellcode from the .exe and copies the resulting binary
# to output_directory.
#
# `scfw` must be configured before this function is called.
function(vmi_extract_shellcode target_name output_directory)
    if(NOT ARGC EQUAL 2)
        message(
            FATAL_ERROR
            "vmi_extract_shellcode requires a target and output directory"
        )
    endif()

    if(NOT COMMAND scfw_extract_shellcode)
        message(
            FATAL_ERROR
            "vmi_extract_shellcode requires scfw_extract_shellcode()"
        )
    endif()

    scfw_extract_shellcode(${target_name})

    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_custom_command(
            TARGET ${target_name}
            POST_BUILD
            COMMAND
                ${CMAKE_COMMAND} -E make_directory
                "${output_directory}"
            COMMAND
                ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE_DIR:${target_name}>/${target_name}.bin"
                "${output_directory}/${target_name}.bin"
            COMMENT "Publishing shellcode: ${target_name}.bin"
            VERBATIM
        )
    endif()
endfunction()
