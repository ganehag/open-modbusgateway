#
# To build this software the RUT SDK is required.
# As of right now (Feb 2020) I am not able to build (in Debian stable) the
# Toolchain (or anything) in the SDK due to a bug in m4 that
# has to do with glibc2.28.
#
# So to get a working Toolchain, to build a binary, I had to use Docker
# to get a working environment using Debian 9.
#
# To use this Makefile you will need to change the STAGING_DIR below to
# the location of a working SDK.
#

LIBMODBUS_VERSION=3.1.6

# HOST_TARGET=x86_64-linux-gnu
HOST_TARGET=mips-openwrt-linux

CFLAGS=-O2 -std=c99
LIBMODBUS_BUILD_DIR=build/lib

LIB_DIRS=-L$(PATH_PREFIX)/usr/lib

ifeq ($(HOST_TARGET), x86_64-linux-gnu)
CC = $(HOST_TARGET)-gcc
CFLAGS+=-I$(PATH_PREFIX)/usr/include
CFLAGS+=-I$(PATH_PREFIX)/usr/include/modbus
CFLAGS+=-I./libmodbus-$(LIBMODBUS_VERSION)/src
LIBS=-lmosquitto -lpthread
endif
ifeq ($(HOST_TARGET), mips-openwrt-linux)
export STAGING_DIR=$${HOME}/Downloads/RUTSDK/staging_dir
CC = $(HOST_TARGET)-gcc
PATH_PREFIX=$(STAGING_DIR)/target-mips_34kc_uClibc-0.9.33.2
CFLAGS+=-I$(PATH_PREFIX)/usr/include
CFLAGS+=-I./libmodbus-$(LIBMODBUS_VERSION)/src
LIBS=-lmosquitto -lpthread -lcrypto -lssl -lcares
LIB_DIRS+=-L$(STAGING_DIR)target-mips_34kc_uClibc-0.9.33.2/usr/lib
endif

#
# libmodbus must be included in the binary as there is no libmodbus library on the RUT9XX
#

OBJ = main.o $(LIBMODBUS_BUILD_DIR)/libmodbus.a

modbusgateway: libmodbus-$(LIBMODBUS_VERSION)/src $(OBJ)
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LIBS) $(LIB_DIRS)
	$(HOST_TARGET)-strip modbusgateway

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

libmodbus-$(LIBMODBUS_VERSION).tar.gz:
	wget -O libmodbus-$(LIBMODBUS_VERSION).tar.gz https://libmodbus.org/releases/libmodbus-$(LIBMODBUS_VERSION).tar.gz

libmodbus-$(LIBMODBUS_VERSION)/src: libmodbus-$(LIBMODBUS_VERSION).tar.gz
	tar xzf libmodbus-$(LIBMODBUS_VERSION).tar.gz

build/lib/libmodbus.a: libmodbus-$(LIBMODBUS_VERSION).tar.gz libmodbus-$(LIBMODBUS_VERSION)/configure
	cd libmodbus-$(LIBMODBUS_VERSION) && ./configure --enable-static --host $(HOST_TARGET) --prefix `pwd`/../build && make install

clean:
	rm -rf $(OBJ) modbusgateway build libmodbus-$(LIBMODBUS_VERSION) libmodbus-$(LIBMODBUS_VERSION).tar.gz
