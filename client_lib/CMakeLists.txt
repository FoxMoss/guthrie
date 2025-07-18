add_library(guthrie-client guthrie.c ../gen/packets.pb-c.c)

target_link_libraries(guthrie-client PUBLIC protobuf-c)
target_include_directories(guthrie-client PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ../gen/
)


add_custom_command(TARGET guthrie-client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")
