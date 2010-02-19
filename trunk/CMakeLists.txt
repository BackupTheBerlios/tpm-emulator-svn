# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id$

project(TPM_Emulator C)

cmake_minimum_required(VERSION 2.6)

# enforce out of source build
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" IS_INSOURCE)
if(IS_INSOURCE)
    message(FATAL_ERROR "${PROJECT_NAME} requires an out of source build.")
endif()

# set project and build version
set(${PROJECT_NAME}_VERSION_MAJOR 0)
set(${PROJECT_NAME}_VERSION_MINOR 7)
string(REGEX REPLACE ".*Revision: ([0-9]+).*" "\\1" ${PROJECT_NAME}_VERSION_BUILD "$Revision$")

# create project configuration
if(WIN32)
STRING(REGEX REPLACE "\\\\" "/" PROGRAMFILES "$ENV{PROGRAMFILES}/${PROJECT_NAME}")
set(TPM_LOG_FILE "${PROGRAMFILES}/tpmd.log")
set(TPM_STORAGE_NAME "${PROGRAMFILES}/tpm_emulator-1_2_${${PROJECT_NAME}_VERSION_MAJOR}_${${PROJECT_NAME}_VERSION_MINOR}")
set(TPM_DEVICE_NAME "//./pipe/tpmd:0")
else()
set(TPM_SOCKET_NAME "/var/run/tpm/tpmd_socket:0")
set(TPM_STORAGE_NAME "/var/lib/tpm/tpm_emulator-1_2_${${PROJECT_NAME}_VERSION_MAJOR}_${${PROJECT_NAME}_VERSION_MINOR}")
set(TPM_DEVICE_NAME "/dev/tpm")
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
add_definitions(-Wall -Werror -Wall -Wextra -Wno-unused-parameter -Wpointer-arith -Wcast-align -Wwrite-strings)

# configure CPack
set(CPACK_PACKAGE_VERSION_MAJOR ${${PROJECT_NAME}_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${${PROJECT_NAME}_VERSION_MINOR})
set(CPACK_SOURCE_PACKAGE_FILE_NAME "tpm_emulator-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES ".svn/;/build*")
set(CPACK_GENERATOR "ZIP")
set(CPACK_SET_DESTDIR ON)
include(CPack)

# include root directories
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_BINARY_DIR})

# add internal libraries
add_subdirectory(tpm)
add_subdirectory(mtm)
add_subdirectory(crypto)

# add TDDL
add_subdirectory(tddl)

# add kernel modules
add_subdirectory(tpmd_dev)

# add executables
add_subdirectory(tpmd)

