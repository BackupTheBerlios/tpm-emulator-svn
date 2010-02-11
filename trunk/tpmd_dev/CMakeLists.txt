# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id$

# select matching module sources
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")

set(tpmd_dev_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/linux")
set(tpmd_dev_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/linux")
set(tpmd_dev_OBJ "${tpmd_dev_BINARY_DIR}/tpmd_dev.ko")

elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")

elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")

endif()

# compile module
if(tpmd_dev_OBJ)

file(GLOB tpmd_dev_SRCS "${tpmd_dev_SOURCE_DIR}/*")

add_custom_command(OUTPUT ${tpmd_dev_OBJ}
                   COMMAND cp -r ${tpmd_dev_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
                   COMMAND make -C ${tpmd_dev_BINARY_DIR}
                   DEPENDS ${tpmd_dev_SRCS})

add_custom_target(tpmd_dev ALL DEPENDS ${tpmd_dev_OBJ})

install(CODE "EXECUTE_PROCESS(COMMAND make -C ${tpmd_dev_BINARY_DIR} install)")

endif()

