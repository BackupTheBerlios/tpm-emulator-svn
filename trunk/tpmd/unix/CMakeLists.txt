# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id$

include_directories("${PROJECT_SOURCE_DIR}/tpm")

file(GLOB tpmd_SRCS "*.[h|c]")
add_executable(tpmd ${tpmd_SRCS})
if(MTM_EMULATOR)
add_definitions(-DMTM_EMULATOR)
target_link_libraries(tpmd mtm tpm tpm_crypto)
else()
target_link_libraries(tpmd tpm tpm_crypto)
endif()
install(TARGETS tpmd RUNTIME DESTINATION bin)

