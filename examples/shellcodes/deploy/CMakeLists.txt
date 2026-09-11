add_executable(deploy main.cpp)
target_link_libraries(deploy PRIVATE scfw vmi::shellcode)
set_target_properties(deploy PROPERTIES SCFW_OPT_LTO ON)
vmi_extract_shellcode(deploy "${SHELLCODE_BIN_DIR}")
