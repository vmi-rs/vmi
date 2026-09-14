add_executable(kernel-file main.cpp)
target_link_libraries(kernel-file PRIVATE scfw vmi::shellcode)

# The default LTO level inlines this payload into one oversized function.
# Level 1 inlines less, which is smaller here.
set_target_properties(kernel-file PROPERTIES
    SCFW_OPT_LTO ON
    SCFW_LTO_LEVEL 1
)

vmi_extract_shellcode(kernel-file "${SHELLCODE_BIN_DIR}")
