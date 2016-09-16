CFLAGS?=-Os -g
SFLAGS:=-std=c99 -D_GNU_SOURCE
WFLAGS:=-Wall -Werror
LDFLAGS?=
DESTDIR?=
LIBRARY:=libzstream.so
SSL:=ssl
DYNFLAGS:= -Iprotocol -Iprotocol/http -I. -Icommon
DYNSOURCE:=protocol/http/http.c protocol/http/headers.c protocol/encoding.c protocol/tls.c common/host.c
B64_MACRO?=BASE64_DECODE
HAVE_SNI_FEATURE?=

ifeq (builtin,$(LIBUBOX))
  DYNFLAGS += -Ibuiltin
  DYNSOURCE += builtin/libubox/*.c
else
  DYNFLAGS += -lubox
endif

bindir:=/usr/bin
libdir:=/usr/lib
includedir:=/usr/include

all: $(LIBRARY) $(BINARY)

$(LIBRARY): *.c $(DYNSOURCE)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SFLAGS) $(WFLAGS) -fpic -shared -o $@ $+ $(LDFLAGS) -l$(SSL) $(DYNFLAGS) -D $(B64_MACRO)

install:
	mkdir -p $(DESTDIR)$(bindir)
	cp $(BINARY) $(DESTDIR)$(bindir)
	mkdir -p $(DESTDIR)$(libdir)
	cp $(LIBRARY) $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(includedir)
	cp zstream.h $(DESTDIR)$(includedir)
	mkdir -p $(DESTDIR)$(includedir)/zstream

clean:
	rm -f $(BINARY) $(LIBRARY)


