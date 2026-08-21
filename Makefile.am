SUBDIRS = src test

.PHONY: integration-check

integration-check: all
	$(top_srcdir)/test/run_serial_gateway_integration.sh

EXTRA_DIST = test/run_serial_gateway_integration.sh test/rtu_slave_sim.c
