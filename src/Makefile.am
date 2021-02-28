bin_PROGRAMS = modbusgateway

modbusgateway_SOURCES = main.c

modbusgateway_CFLAGS = -std=gnu99 @MODBUS_CFLAGS@ @MOSQUITTO_CFLAGS@
modbusgateway_LDFLAGS = -lpthread @MODBUS_LIBS@ @MOSQUITTO_LIBS@
