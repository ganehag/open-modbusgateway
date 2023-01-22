bin_PROGRAMS = modbusgateway

modbusgateway_SOURCES = config_parser.c  filters.c  iprange.c  main.c  request.c

# mosquitto, modbus, pthread and libconfig
modbusgateway_CFLAGS = @MOSQUITTO_CFLAGS@ @MODBUS_CFLAGS@
modbusgateway_LDADD = @MOSQUITTO_LIBS@ @MOSQUITTO_LDFLAGS@ @MODBUS_LIBS@ @MODBUS_LDFLAGS@ -lpthread

