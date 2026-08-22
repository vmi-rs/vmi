add_executable(file-transfer main.cpp)
target_link_libraries(file-transfer PRIVATE scfw bridge)
set_target_properties(file-transfer PROPERTIES SCFW_OPT_LTO ON)
scfw_extract_shellcode(file-transfer)
