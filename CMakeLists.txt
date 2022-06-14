# Copyright (c) 2004-2020 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: MIT

project(mera)

option(BUILD_MERA_DEMO "Build MERA demo" ON)

cmake_minimum_required(VERSION 3.14)

include(CMakeParseArguments)
include(.cmake/common.cmake)

include_directories(include)

add_library(mera SHARED src/rte.c src/rte_ib.c src/rte_ob.c
            include/microchip/ethernet/rte/api.h
            include/microchip/ethernet/rte/api/main.h)

target_include_directories(mera
    PUBLIC
        $<BUILD_INTERFACE:${mera_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
)

# install the library
install(TARGETS mera
	EXPORT mera-targets
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
)

# install header files
install(DIRECTORY "include/"
	TYPE INCLUDE
	COMPONENT mera
)

# install export target and config for find_package
install(EXPORT mera-targets DESTINATION lib/cmake/mera)
include(CMakePackageConfigHelpers)
configure_package_config_file(
	"meraConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/meraConfig.cmake"
	INSTALL_DESTINATION "lib/cmake/mera"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/meraConfig.cmake" DESTINATION "lib/cmake/mera")

export(EXPORT mera-targets
       FILE ${CMAKE_CURRENT_BINARY_DIR}/mera-targets.cmake)

export(PACKAGE mera)

if (${BUILD_MERA_DEMO})
    find_library(JSON_LIB json-c)
    mark_as_advanced(JSON_LIB)
    if (JSON_LIB)
        add_subdirectory(demo)
    endif()
endif()

