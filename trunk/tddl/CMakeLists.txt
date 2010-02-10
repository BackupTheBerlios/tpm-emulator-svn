# Software-based TPM/MTM Emulator
# Copyright (C) 2010 Mario Strasser <mast@gmx.net>
#
# $Id$

if(UNIX)

add_subdirectory(unix)

elseif(WIN32)

add_subdirectory(windows)

endif()

