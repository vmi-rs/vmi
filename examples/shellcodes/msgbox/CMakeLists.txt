add_executable(msgbox main.cpp)
target_link_libraries(msgbox PRIVATE scfw vmi::shellcode)

# The default LTO level inlines this payload into one oversized function.
# Level 1 inlines less, which is smaller here.
set_target_properties(msgbox PROPERTIES SCFW_OPT_LTO ON SCFW_LTO_LEVEL 1)

vmi_extract_shellcode(msgbox "${SHELLCODE_BIN_DIR}")
