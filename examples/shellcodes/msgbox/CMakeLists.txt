add_executable(msgbox main.cpp)
target_link_libraries(msgbox PRIVATE scfw bridge)
set_target_properties(msgbox PROPERTIES SCFW_OPT_LTO ON)
scfw_extract_shellcode(msgbox)
