SUBDIRS = src test

.PHONY: integration-check coverage

integration-check: all
	$(top_srcdir)/test/run_serial_gateway_integration.sh

coverage:
	$(MAKE) clean
	$(MAKE) check CFLAGS='$(CFLAGS) -O0 --coverage'
	gcovr --root $(top_srcdir) --exclude 'test/' --txt coverage.txt

EXTRA_DIST = test/run_serial_gateway_integration.sh test/rtu_slave_sim.c \
    examples/automation.lua.example
