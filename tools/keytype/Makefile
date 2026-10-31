CFLAGS ?= -O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
PKGS = wayland-client xkbcommon
PROTOCOL = virtual-keyboard-unstable-v1

keytype: keytype.c $(PROTOCOL)-client-protocol.h $(PROTOCOL)-protocol.c
	$(CC) $(CFLAGS) $(shell pkg-config --cflags $(PKGS)) keytype.c $(PROTOCOL)-protocol.c -o $@ $(LDFLAGS) $(shell pkg-config --libs $(PKGS))

$(PROTOCOL)-client-protocol.h: $(PROTOCOL).xml
	wayland-scanner client-header $< $@

$(PROTOCOL)-protocol.c: $(PROTOCOL).xml
	wayland-scanner private-code $< $@

clean:
	rm -f keytype $(PROTOCOL)-client-protocol.h $(PROTOCOL)-protocol.c

.PHONY: clean
