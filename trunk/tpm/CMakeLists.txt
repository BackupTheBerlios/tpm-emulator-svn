# Software-based TPM/MTM Emulator
# Copyright (C) 2010 Mario Strasser <mast@gmx.net>
#
# $Id$

file(GLOB tpm_SRCS "*.[h|c]")
add_library(tpm STATIC ${tpm_SRCS})

