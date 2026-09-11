add_executable(msgbox main.cpp)
target_link_libraries(msgbox PRIVATE scfw vmi::shellcode)
set_target_properties(msgbox PROPERTIES SCFW_OPT_LTO ON)
vmi_extract_shellcode(msgbox "${SHELLCODE_BIN_DIR}")
