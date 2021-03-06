#!/usr/bin/make -f

# Makefile for msva-perl

# © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
# Licensed under GPL v3 or later

VERSION := $(shell dpkg-parsechangelog -lChangelog | grep ^Version: | cut -f2 -d\ )
DEBIAN_VERSION=`dpkg-parsechangelog | grep ^Version: | cut -f2 -d\ `

MANPAGES=msva-perl.1 msva-query-agent.1

all: $(MANPAGES) Crypt/Monkeysphere/MSVA.pm

%.1: %
	pod2man $< $@

Crypt/Monkeysphere/MSVA.pm: Changelog
	sed -i "s/^  \\\$$VERSION = '[a-z0-9.~A-Z]*';$$/  \$$VERSION = '$(VERSION)';/" $@

clean: 
	rm -f $(MANPAGES)

debian-package:
	git buildpackage -uc -us

upstream-tag:
	git tag -s msva-perl/$(VERSION) -m "releasing msva-perl version $(VERSION)"
debian-tag:
	git tag -s msva-perl_debian/$(DEBIAN_VERSION) -m "tagging msva-perl debian packaging version $(DEBIAN_VERSION)"

.PHONY: upstream-tag debian-package debian-tag all clean
