# Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

message(STATUS "CMAKE_TOOLCHAIN_FILE='${CMAKE_TOOLCHAIN_FILE}'")

find_library(JSON_LIB json-c)
if(NOT JSON_LIB)
      message(FATAL_ERROR "json-c not found")
endif()
add_library(rte-json-c SHARED IMPORTED GLOBAL) # GLOBAL -> if outside src tree
set_property(TARGET rte-json-c PROPERTY IMPORTED_LOCATION ${JSON_LIB})

add_executable(lan9662-rte-demo main.c)

target_link_libraries(lan9662-rte-demo lan9662-rte rte-json-c)

