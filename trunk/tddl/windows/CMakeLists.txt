# Software-based Trusted Platform Module (TPM) Emulator
# Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
#
# $Id$

set(tddl_SRCS "tddl.c" "tddl.h")
add_library(tddl SHARED ${tddl_SRCS})
set_target_properties(tddl PROPERTIES OUTPUT_NAME ifxtpm)
set_target_properties(tddl PROPERTIES PREFIX "")

install(TARGETS tddl RUNTIME DESTINATION lib)
install(FILES "tddl.h" DESTINATION include)

