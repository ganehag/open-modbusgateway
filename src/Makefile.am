bin_PROGRAMS = omg

omg_SOURCES = config_parser.c  filters.c  iprange.c  main.c  request.c

# mosquitto, modbus, pthread and libconfig
omg_CFLAGS = @MOSQUITTO_CFLAGS@ @MODBUS_CFLAGS@
omg_LDADD = @MOSQUITTO_LIBS@ @MOSQUITTO_LDFLAGS@ @MODBUS_LIBS@ @MODBUS_LDFLAGS@ -lpthread
