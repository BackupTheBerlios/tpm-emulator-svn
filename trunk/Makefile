# Software-Based Trusted Platform Module (TPM) Emulator for Linux
# Copyright (C) 2006 Mario Strasser <mast@gmx.net>
#
# $Id$

# tpm settings
PACKAGE_NAME   := tpm_emulator
VERSION_MAJOR  := 0
VERSION_MINOR  := 5
VERSION_BUILD  := $(shell date +"%s")
VERSION_SUFFIX := .2beta

SUBDIRS := tpmd tpmd_dev tddl

all: version all-recursive

version:
	@echo "#ifndef _TPM_VERSION_H_" > tpm/tpm_version.h
	@echo "#define _TPM_VERSION_H_" >> tpm/tpm_version.h
	@echo "#define VERSION_MAJOR $(VERSION_MAJOR)" >> tpm/tpm_version.h
	@echo "#define VERSION_MINOR $(VERSION_MINOR)" >> tpm/tpm_version.h
	@echo "#define VERSION_BUILD $(VERSION_BUILD)" >> tpm/tpm_version.h
	@echo "#endif /* _TPM_VERSION_H_ */" >> tpm/tpm_version.h

clean: clean-recursive
	rm -f tpm/tpm_version.h

install: install-recursive

all-recursive clean-recursive install-recursive:
	@target=`echo $@ | sed s/-recursive//`; \
	for subdir in $(SUBDIRS); do \
		echo "Making $$target in $$subdir"; \
		$(MAKE) -C $$subdir $$target || exit -1; \
	done

user: version
	@$(MAKE) -C tpmd all || exit -1
	@$(MAKE) -C tddl all || exit -1

modules: version
	@$(MAKE) -C tpmd_dev all || exit -1

user_install: user
	@$(MAKE) -C tpmd install || exit -1
	@$(MAKE) -C tddl install || exit -1

modules_install: modules
	@$(MAKE) -C tpmd_dev install || exit -1

DIRS    := . tpm crypto tpmd tpmd_dev tddl tpmd_dev_openbsd
DISTSRC := $(foreach dir, $(DIRS), $(wildcard $(dir)/*.c))
DISTSRC += $(foreach dir, $(DIRS), $(wildcard $(dir)/*.h))
DIRS    := . tpmd tpmd_dev tddl tpmd_dev_openbsd
DISTSRC += $(foreach dir, $(DIRS), $(dir)/Makefile)
DISTSRC += ./README ./AUTHORS ./ChangeLog tpmd_dev/tpmd_dev.rules.in
DISTDIR := tpm_emulator-$(VERSION_MAJOR).$(VERSION_MINOR)$(VERSION_SUFFIX)

dist: $(DISTSRC)
	@rm -rf $(DISTDIR); mkdir $(DISTDIR)
	@cp --parents $(DISTSRC) $(DISTDIR)/
	tar -chzf $(DISTDIR).tar.gz $(DISTDIR)
	@rm -rf $(DISTDIR)

.PHONY: all version clean install dist

