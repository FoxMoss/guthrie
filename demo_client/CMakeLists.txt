add_executable(guthrie-demo
  main.c
)

target_link_libraries(guthrie-demo guthrie-client)

add_custom_command(TARGET guthrie-demo POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")

