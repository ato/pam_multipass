CFLAGS = -fPIC -W -Wall -O2 -std=c99
LDFLAGS = -lpam
CFLAGS += $(shell pkg-config --cflags json)
LDFLAGS += $(shell pkg-config --libs json)
prefix = /usr/local

#
# Try to guess the right place to install to.  Someone write me a configure script.
#

# recent Debian/Ubuntu
multiarch = $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)
ifneq ($(multiarch),)
libdir = /lib/$(multiarch)
else
# Fedora x86_64
ifeq ($(shell [ -d /lib64/security ] && uname -i), x86_64)
libdir = /lib64
endif
endif
# most others
ifndef libdir
libdir = /lib
endif

all: pam_multipass.so pam_multipass_test $(multiarch)

pam_multipass_test: pam_multipass.o crypt_blowfish.o pam_multipass_test.o

pam_multipass.so: pam_multipass.o crypt_blowfish.o
	$(LD) $(LDFLAGS) -x --shared -o $@ $^

install: pam_multipass.so
	install -o root -g root -m 755 pam_multipass.so $(libdir)/security/pam_multipass.so
	install -o root -g root -m 755 multipass.py $(prefix)/bin/multipass

clean:
	rm -f pam_multipass.so pam_multipass_test *.o *~
