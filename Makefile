CC=gcc
BUILDDIR=bin
OBJECTDIR=$(BUILDDIR)/objects
CFLAGS=-Wall -Werror -std=gnu99 -g
IBCRYPTFLAGS=
ifeq ($(NO-OPTIMIZE),1)
	IBCRYPTFLAGS+=NO-OPTIMIZE=1
else
	CFLAGS+=-O3
endif
LINKFLAGS=-flto

LIBINC=-I libibur/bin -I ibcrypt/bin/include -pthread
LIBS=-Libcrypt/bin -libcrypt

DIRS=server client inet crypto util
BUILDDIRS=$(patsubst %,$(OBJECTDIR)/%,$(DIRS))

SOURCES:=
CLIENTSOURCES:=
SERVERSOURCES:=

include $(patsubst %,%/inc.mk,$(DIRS))

CLIENTSOURCES+=$(SOURCES)
SERVERSOURCES+=$(SOURCES)

CLIENTOBJECTS:=$(patsubst %.c,$(OBJECTDIR)/%.o,$(CLIENTSOURCES))
SERVEROBJECTS:=$(patsubst %.c,$(OBJECTDIR)/%.o,$(SERVERSOURCES))

.PHONY: all server client install clean libs

all: server client

server: bin libs $(SERVEROBJECTS)
	$(CC) $(LINKFLAGS) $(SERVEROBJECTS) $(LIBS) -o $(BUILDDIR)/ibchat-server

client: bin libs $(CLIENTOBJECTS)
	$(CC) $(LINKFLAGS) $(CLIENTOBJECTS) $(LIBS) -o $(BUILDDIR)/ibchat

libs:
	git submodule update --init --recursive
	$(MAKE) -C ibcrypt $(IBCRYPTFLAGS)
	$(MAKE) -C libibur

$(OBJECTDIR)/%.o: %.c $(OBJECTDIR)
	$(CC) $(CFLAGS) -c $(LIBINC) $< -o $@

$(BUILDDIR):
	mkdir -p $(BUILDDIR) $(BUILDDIRS) $(OBJECTDIR)

clean:
	rm -r bin

