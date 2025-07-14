find_package(Protobuf REQUIRED)
set(PROTO_PATH ../proto/cpp)

add_executable(guthrie
  main.cpp
  ${PROTO_PATH}/packets.pb.cc
  ${PROTO_PATH}/buf/validate/validate.pb.cc
)

# TODO: disable in release
add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

include(FetchContent)

FetchContent_Declare(
    protovalidate_cc
    URL https://github.com/bufbuild/protovalidate-cc/releases/download/v0.8.0/protovalidate-cc-0.8.0.tar.gz
)

FetchContent_MakeAvailable(protovalidate_cc)

target_link_libraries(guthrie PRIVATE protobuf::libprotobuf protovalidate_cc::protovalidate_cc)
target_include_directories(guthrie PRIVATE
    ${PROTO_PATH}
)


add_custom_command(TARGET guthrie POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")

