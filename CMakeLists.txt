cmake_minimum_required(VERSION 3.16)
project(pkt C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(pkt
  src/main.c
  src/log.c
  src/rx_pcap.c
)

target_include_directories(pkt PRIVATE include)

target_link_libraries(pkt pcap)

target_compile_options(pkt PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Wshadow
  -Wformat=2
  -Wundef
  -Werror
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_options(pkt PRIVATE -O0 -g3)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_compile_options(pkt PRIVATE -O3)
endif()