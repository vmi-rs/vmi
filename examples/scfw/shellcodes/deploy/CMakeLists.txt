add_executable(deploy main.cpp)
target_link_libraries(deploy PRIVATE scfw bridge)
set_target_properties(deploy PROPERTIES SCFW_OPT_LTO ON)
scfw_extract_shellcode(deploy)
