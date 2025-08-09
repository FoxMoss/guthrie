set(PROTO_PATH ../proto/cpp)

add_executable(guthrie
  main.cpp
)

include(FetchContent)

if(CMAKE_BUILD_TYPE STREQUAL "Release") # only build release on musl
  add_compile_options(
        -static
        -O3
    )

    add_link_options(
        -static
    )

    target_compile_options(guthrie PRIVATE
        -static
        -O3
    )

    target_link_options(guthrie PRIVATE
        -static
    )


    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")
endif()

set(protobuf_BUILD_TESTS OFF)
set(protobuf_INSTALL OFF)
set(protobuf_FORCE_FETCH_DEPENDENCIES ON)

FetchContent_Declare(protobuf
  GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
  GIT_TAG        v31.1
)
FetchContent_MakeAvailable(protobuf)
include(${protobuf_SOURCE_DIR}/cmake/protobuf-generate.cmake)

add_library(packets OBJECT ../proto/packets.proto)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/gen)

protobuf_generate(
    TARGET packets
    LANGUAGE cpp
    PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen
    IMPORT_DIRS ${PROTOBUF_IMPORT_PATH}
                ${CMAKE_CURRENT_SOURCE_DIR}
                ../proto/
)

target_link_libraries(packets PUBLIC protobuf::libprotobuf)
target_include_directories(packets PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/gen)

target_link_libraries(guthrie packets sqlite3)
target_include_directories(guthrie PRIVATE)

install(TARGETS guthrie DESTINATION bin)

set(CPACK_PACKAGE_NAME "guthrie-server") 
set(CPACK_PACKAGE_AUTHOR "FoxMoss") 
set(CPACK_PACKAGE_CONTACT "foxmoss@mediaology.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 2)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_DESCRIPTION "Client library for the Guthrie messaging protocol")
set(CPACK_INSTALL_PREFIX "/usr/local") 

set(CPACK_GENERATOR "TGZ;DEB") 

include(CPack)

add_custom_command(TARGET guthrie POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")

