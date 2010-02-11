# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id$

include_directories("${PROJECT_SOURCE_DIR}/tpm")

file(GLOB tpmd_SRCS "*.[h|c]")
add_executable(tpmd ${tpmd_SRCS})
target_link_libraries(tpmd tpm crypto)
install(TARGETS tpmd RUNTIME DESTINATION bin)

