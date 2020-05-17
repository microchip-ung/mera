# Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

project(lan9662rte)

option(BUILD_LAN9662_RTE_DEMO "Build LAN9662 RTE demo" ON)

cmake_minimum_required(VERSION 2.8.12)

include(CMakeParseArguments)
include(.cmake/common.cmake)

include_directories(include)

add_library(lan9662-rte SHARED src/rte.c)

if (${BUILD_LAN9662_RTE_DEMO})
    find_library(JSON_LIB json-c)
    mark_as_advanced(JSON_LIB)
    if (JSON_LIB)
        add_subdirectory(demo)
    endif()
endif()

