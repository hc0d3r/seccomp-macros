.PHONY: install uninstall examples

INSTALLDIR?=/usr/include

install:
	cp include/seccomp-macros.h $(INSTALLDIR)/

uninstall:
	rm -f $(INSTALLDIR)/seccomp-macros.h

examples:
	$(MAKE) -C examples
