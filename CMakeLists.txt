cmake_minimum_required(VERSION 3.31)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(Guthrie)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_LIBRARY "Build just the library" On)

if(${BUILD_LIBRARY})
  add_subdirectory(client_lib)
else()
  add_subdirectory(src)
  add_subdirectory(client_lib)
  add_subdirectory(demo_client)
endif()
