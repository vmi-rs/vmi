add_executable(deploy main.cpp)
target_link_libraries(deploy PRIVATE scfw vmi::shellcode)
set_target_properties(deploy PROPERTIES SCFW_OPT_LTO ON)

# Unlike the other payloads, this one is smaller at -Oz. The frontend
# optimization level is not a target property, so it goes on the source
# (see the scfw README).
set_source_files_properties(main.cpp PROPERTIES COMPILE_OPTIONS -Oz)

vmi_extract_shellcode(deploy "${SHELLCODE_BIN_DIR}")
