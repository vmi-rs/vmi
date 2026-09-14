add_executable(file-transfer main.cpp)
target_link_libraries(file-transfer PRIVATE scfw vmi::shellcode)

# The default LTO level inlines this payload into one oversized function.
# Level 1 inlines less, which is smaller here.
set_target_properties(file-transfer PROPERTIES SCFW_OPT_LTO ON SCFW_LTO_LEVEL 1)

vmi_extract_shellcode(file-transfer "${SHELLCODE_BIN_DIR}")
