cmake_minimum_required(VERSION 3.31)

project(monad_cxx_env)

add_subdirectory("monad-execution/third_party/quill" "quill-build")

add_library(monad_cxx_env "${PROJECT_SOURCE_DIR}/include/category/ffi/cxx_env.h"
                          "${PROJECT_SOURCE_DIR}/src/cxx_env.cpp")

target_include_directories(monad_cxx_env PRIVATE "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(monad_cxx_env PUBLIC quill)
