# Software-based TPM/MTM Emulator
# Copyright (C) 2010 Mario Strasser <mast@gmx.net>
#
# $Id$

include_directories("${PROJECT_SOURCE_DIR}/tpm")

file(GLOB tpmd_SRCS "*.[h|c]")
add_executable(tpmd ${tpmd_SRCS})
target_link_libraries(tpmd tpm crypto)

