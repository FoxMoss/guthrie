add_library(guthrie-client guthrie.c ../gen/packets.pb-c.c)

target_link_libraries(guthrie-client PUBLIC protobuf-c)
target_include_directories(guthrie-client PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ../gen/
)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/../gen/pakcets.pb-c.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../proto/packets.proto
    COMMAND protoc --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/../proto 
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto/packets.proto --c_out=${CMAKE_CURRENT_SOURCE_DIR}/../gen/
    COMMENT "Update packets protobuild")

add_custom_command(TARGET guthrie-client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")
