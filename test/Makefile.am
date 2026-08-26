AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_builddir)

noinst_HEADERS = mqtt_test_helpers.h test.h

check_PROGRAMS = openmmg_tests
TESTS = $(check_PROGRAMS)

openmmg_tests_SOURCES = \
    mqtt_test_helpers.c \
    test.c \
    test_config.c \
    test_filters.c \
    test_ip_in_range.c \
    test_mqtt_client.c \
    $(top_srcdir)/src/config_parser.c \
    $(top_srcdir)/src/filters.c \
    $(top_srcdir)/src/iprange.c \
    $(top_srcdir)/src/log.c \
    $(top_srcdir)/src/mqtt_client.c

if BUILD_LUA
openmmg_tests_SOURCES += $(top_srcdir)/src/automation.c test_automation.c
else
openmmg_tests_SOURCES += $(top_srcdir)/src/automation_stub.c test_automation_stub.c
endif

openmmg_tests_CFLAGS = $(CUNIT_CFLAGS) $(LUA_CFLAGS) $(MODBUS_CFLAGS)
openmmg_tests_LDADD = $(CUNIT_LIBS) $(LUA_LIBS) $(MODBUS_LIBS)

.PHONY: run integration-check

run: check

integration-check: $(top_builddir)/src/openmmg
	$(top_srcdir)/test/run_serial_gateway_integration.sh
