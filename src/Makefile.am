bin_PROGRAMS = openmmg

AM_CPPFLAGS = -I$(srcdir) -I$(top_builddir)

openmmg_SOURCES = config_parser.c filters.c iprange.c main.c request.c log.c mqtt_client.c
noinst_HEADERS = config_parser.h filters.h iprange.h log.h mqtt_client.h request.h automation.h

if BUILD_LUA
openmmg_SOURCES += automation.c
else
openmmg_SOURCES += automation_stub.c
endif

# mosquitto, modbus, pthread and libconfig
openmmg_CFLAGS = @MOSQUITTO_CFLAGS@ @MODBUS_CFLAGS@ @LUA_CFLAGS@
openmmg_LDADD = @MOSQUITTO_LIBS@ @MOSQUITTO_LDFLAGS@ @MODBUS_LIBS@ @MODBUS_LDFLAGS@ @LUA_LIBS@ -lpthread

AM_LDFLAGS = -s
AM_CFLAGS = $(CFLAGS)
