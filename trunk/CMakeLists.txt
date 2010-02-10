# Software-based TPM/MTM Emulator
# Copyright (C) 2010 Mario Strasser <mast@gmx.net>
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
set(${PROJECT_NAME}_MAJOR_VERSION 0)
set(${PROJECT_NAME}_MINOR_VERSION 7)
string(REGEX REPLACE ".*Revision: ([0-9]+).*" "\\1" ${PROJECT_NAME}_BUILD_VERSION "$Revision$")

# create project configuration
set(TPM_SOCKET_NAME "/var/run/tpm/tpmd_socket:0")
set(TPM_STORAGE_NAME "/var/lib/tpm/tpm_emulator-1.2.${${PROJECT_NAME}_MAJOR_VERSION}.${${PROJECT_NAME}_MINOR_VERSION}")
set(TPM_DEVICE_NAME "/dev/tpm")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# configure CPack

include_directories(${CMAKE_SOURCE_DIR})

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

