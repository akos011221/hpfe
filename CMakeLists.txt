cmake_minimum_required(VERSION 3.16)
project(hpfe C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(hpfe
  src/main.c
  src/log.c
)

target_include_directories(hpfe PRIVATE include)

target_compile_options(hpfe PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Wshadow
  -Wformat=2
  -Wundef
  -Werror # treat warnings as errors.
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(hpfe PRIVATE -O0 -g3)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(hpfe PRIVATE -O3)
endif()