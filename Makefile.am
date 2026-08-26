SUBDIRS = src

if BUILD_TESTS
SUBDIRS += test
endif

.PHONY: integration-check coverage

if BUILD_LUA
integration-check: all
	$(top_srcdir)/test/run_serial_gateway_integration.sh
else
integration-check:
	@echo "Lua integration tests require ./configure --enable-lua"
	@false
endif

coverage:
	$(MAKE) clean
	$(MAKE) check CFLAGS='$(CFLAGS) -O0 --coverage'
	gcovr --root $(top_srcdir) --exclude 'test/' --txt coverage.txt

EXTRA_DIST = test/run_serial_gateway_integration.sh test/rtu_slave_sim.c \
    examples/automation.lua.example openwrt/Config.in openwrt/Makefile \
    openwrt/openmmg.config openwrt/openmmg.init
