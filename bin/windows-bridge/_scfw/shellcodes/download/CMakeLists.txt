add_executable(download main.cpp)
target_link_libraries(download PRIVATE scfw bridge)
set_target_properties(download PROPERTIES SCFW_OPT_LTO OFF)
scfw_extract_shellcode(download)
