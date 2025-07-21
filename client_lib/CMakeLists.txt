add_library(guthrie-client guthrie.c packets.pb-c.c)

target_link_libraries(guthrie-client protobuf-c)
target_include_directories(guthrie-client PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

install(TARGETS guthrie-client DESTINATION lib)
install(FILES guthrie.h packets.pb-c.h
        DESTINATION include)

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")

set(CPACK_PACKAGE_NAME "libguthrie-client") 
set(CPACK_PACKAGE_AUTHOR "FoxMoss") 
set(CPACK_PACKAGE_CONTACT "foxmoss@mediaology.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
set(CPACK_PACKAGE_VERSION_MAJOR 0)
set(CPACK_PACKAGE_VERSION_MINOR 1)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_DESCRIPTION "Client library for the Guthrie messaging protocol")
set(CPACK_INSTALL_PREFIX "/usr/local") 

set(CPACK_GENERATOR "TGZ;DEB") 

include(CPack)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/packets.pb-c.c
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../proto/packets.proto
    COMMAND protoc --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/../proto 
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto/packets.proto --c_out=${CMAKE_CURRENT_SOURCE_DIR}/
    COMMENT "Update packets protobuild")

add_custom_command(TARGET guthrie-client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/compile_commands.json
        ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Add clangd to the src directory")
