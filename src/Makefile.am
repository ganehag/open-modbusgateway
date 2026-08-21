bin_PROGRAMS = openmmg

AM_CPPFLAGS = -I$(srcdir)

openmmg_SOURCES = config_parser.c filters.c iprange.c main.c request.c log.c mqtt_client.c automation.c
noinst_HEADERS = config_parser.h filters.h iprange.h log.h mqtt_client.h request.h automation.h

# mosquitto, modbus, pthread and libconfig
openmmg_CFLAGS = @MOSQUITTO_CFLAGS@ @MODBUS_CFLAGS@ @LUA_CFLAGS@
openmmg_LDADD = @MOSQUITTO_LIBS@ @MOSQUITTO_LDFLAGS@ @MODBUS_LIBS@ @MODBUS_LDFLAGS@ @LUA_LIBS@ -lpthread

AM_LDFLAGS = -s
AM_CFLAGS = $(CFLAGS)
