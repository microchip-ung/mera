# Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

message(STATUS "CMAKE_TOOLCHAIN_FILE='${CMAKE_TOOLCHAIN_FILE}'")

find_library(JSON_LIB json-c)
if(NOT JSON_LIB)
      message(FATAL_ERROR "json-c not found")
endif()
add_library(rte-json-c SHARED IMPORTED GLOBAL) # GLOBAL -> if outside src tree
set_property(TARGET rte-json-c PROPERTY IMPORTED_LOCATION ${JSON_LIB})

set(RPC_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/../include/lan9662/rte/rte.h)

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/rpc-ag/mera-rpc.h ${CMAKE_CURRENT_BINARY_DIR}/rpc-ag/mera-rpc.c
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/rpc-gen.rb -b ${CMAKE_CURRENT_SOURCE_DIR}/.. -o ${CMAKE_CURRENT_BINARY_DIR}/rpc-ag ${RPC_HDRS}
                   DEPENDS ${RPC_HDRS}
                   COMMENT "Generate mera-rpc.h/mera-rpc.c")

add_custom_target(rpc_src DEPENDS
                  ${CMAKE_CURRENT_BINARY_DIR}/rpc-ag/mera-rpc.h
                  ${CMAKE_CURRENT_BINARY_DIR}/rpc-ag/mera-rpc.c)

include_directories(.)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/rpc-ag)

add_library(mera-demo-lib STATIC cli.c trace.c uio.c json_rpc.c ${CMAKE_CURRENT_BINARY_DIR}/rpc-ag/mera-rpc.c)

add_executable(mera-demo main.c)
add_executable(mera-cmd cmd.c)

target_link_libraries(mera-demo mera-demo-lib mera rte-json-c)

