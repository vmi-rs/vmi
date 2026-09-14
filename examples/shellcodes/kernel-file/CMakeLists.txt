add_executable(kernel-file main.cpp)
target_link_libraries(kernel-file PRIVATE scfw vmi::shellcode)
set_target_properties(kernel-file PROPERTIES SCFW_OPT_LTO ON)
vmi_extract_shellcode(kernel-file "${SHELLCODE_BIN_DIR}")
