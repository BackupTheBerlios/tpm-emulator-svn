# Software-based TPM/MTM Emulator
# Copyright (C) 2010 Mario Strasser <mast@gmx.net>
#
# $Id$

set(tddl_SRCS "tddl.c" "tddl.h")
add_library(tddl SHARED ${tddl_SRCS})
set_target_properties(tddl PROPERTIES SOVERSION "1.2"
  VERSION "1.2.${${PROJECT_NAME}_MAJOR_VERSION}.${${PROJECT_NAME}_MINOR_VERSION}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_tddl test_tddl.c)
target_link_libraries(test_tddl tddl)

