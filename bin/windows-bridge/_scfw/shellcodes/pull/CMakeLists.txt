add_executable(pull main.cpp)
target_link_libraries(pull PRIVATE scfw bridge)
set_target_properties(pull PROPERTIES SCFW_OPT_LTO OFF)
scfw_extract_shellcode(pull)
