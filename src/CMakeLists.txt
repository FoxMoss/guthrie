set(PROTO_PATH ../proto/cpp)

add_executable(guthrie
  main.cpp
)

include(FetchContent)

FetchContent_Declare(
    protovalidate_cc
    GIT_REPOSITORY https://github.com/FoxMoss/protovalidate-cc
    GIT_TAG main
)

FetchContent_MakeAvailable(protovalidate_cc)

FetchContent_GetProperties(protovalidate)


# add_library(packets OBJECT packets.proto)
# file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen)
# protobuf_generate(
#     TARGET packets 
#     LANGUAGE cpp
#     PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen
#     IMPORT_DIRS ${protovalidate_SOURCE_DIR}/proto/protovalidate
#                 ${PROTOBUF_IMPORT_PATH}
#                 ${CMAKE_CURRENT_SOURCE_DIR}
# )


# target_link_libraries(packets PUBLIC )

find_package(Protobuf CONFIG)

add_library(packets OBJECT packets.proto)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen)
protobuf_generate(
    TARGET packets
    LANGUAGE cpp
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen
    IMPORT_DIRS ${protovalidate_SOURCE_DIR}/proto/protovalidate
                ${PROTOBUF_IMPORT_PATH}
                ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(packets PUBLIC protovalidate_cc::protovalidate_cc)
target_include_directories(packets PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/gen)

find_package (SQLite3)

target_link_libraries(guthrie packets ${SQLite3_LIBRARIES})
target_include_directories(guthrie PRIVATE
  ${SQLite3_INCLUDE_DIRS}
)

add_custom_command(TARGET guthrie POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")

