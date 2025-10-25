#include <errno.h>
#include <modbus/modbus.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile sig_atomic_t running = 1;

static void
handle_signal(int signo) {
    (void)signo;
    running = 0;
}

int
main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(
            stderr,
            "Usage: %s <device> [baud parity data_bits stop_bits slave_id]\n",
            argv[0]);
        return EXIT_FAILURE;
    }

    const char *device = argv[1];
    int baud = (argc > 2) ? atoi(argv[2]) : 115200;
    char parity = (argc > 3) ? argv[3][0] : 'N';
    int data_bits = (argc > 4) ? atoi(argv[4]) : 8;
    int stop_bits = (argc > 5) ? atoi(argv[5]) : 1;
    int slave_id = (argc > 6) ? atoi(argv[6]) : 1;

    modbus_t *ctx = modbus_new_rtu(device, baud, parity, data_bits, stop_bits);
    if (ctx == NULL) {
        fprintf(stderr, "modbus_new_rtu failed: %s\n", modbus_strerror(errno));
        return EXIT_FAILURE;
    }

    if (modbus_set_slave(ctx, slave_id) == -1) {
        fprintf(
            stderr, "modbus_set_slave failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "Unable to connect: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    modbus_mapping_t *mb_mapping =
        modbus_mapping_new(0, 0, 64, 64); // holding and input registers
    if (mb_mapping == NULL) {
        fprintf(
            stderr, "Failed to allocate mapping: %s\n", modbus_strerror(errno));
        modbus_close(ctx);
        modbus_free(ctx);
        return EXIT_FAILURE;
    }

    // Populate deterministic values for reads
    mb_mapping->tab_registers[0] = 100;
    mb_mapping->tab_registers[1] = 200;
    mb_mapping->tab_input_registers[0] = 300;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    uint8_t query[MODBUS_RTU_MAX_ADU_LENGTH];

    while (running) {
        int rc = modbus_receive(ctx, query);
        if (rc > 0) {
            if (modbus_reply(ctx, query, rc, mb_mapping) == -1) {
                break;
            }
        } else if (rc == -1) {
            break;
        }
    }

    modbus_mapping_free(mb_mapping);
    modbus_close(ctx);
    modbus_free(ctx);

    return EXIT_SUCCESS;
}
