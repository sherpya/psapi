cmake_minimum_required(VERSION 3.1)
project(psapi)

if (${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
    set(CMAKE_C_FLAGS "-Wall")
    set(CMAKE_C_FLAGS_DEBUG "-g3")
    set(CMAKE_C_FLAGS_RELEASE "-O2 -s")
    set(CMAKE_SHARED_LIBRARY_CREATE_C_FLAGS "-shared -nostdlib")
endif()

add_library(psapi SHARED psapi.c psapi.rc psapi.def)
set_target_properties(psapi PROPERTIES PREFIX "")
