#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/config_parser.h"
#include "../src/filters.h"
#include "../src/log.h"
#include "../src/mqtt_client.h"
#include "../src/request.h"
#include "mqtt_test_helpers.h"
#include "test.h"

#define silence_logs mqtt_test_silence_logs
#define setup_basic_config mqtt_test_setup_serial_config
#define add_serial_filter mqtt_test_add_serial_filter
#define make_message mqtt_test_make_message

void
test_mqtt_format1_slave_override(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);
    gateway.slave_id = 17;
    add_serial_filter(&config, "ttyusb0", 17, 3, 0, 65535);

    const char *payload = "1 42 ttyusb0 5 9 3 10 2";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    request_t *captured = mqtt_test_captured_request();
    CU_ASSERT_PTR_NOT_NULL_FATAL(captured);
    CU_ASSERT_STRING_EQUAL(captured->serial_id, "ttyusb0");
    CU_ASSERT_STRING_EQUAL(captured->serial_device, "/dev/ttyUSB0");
    CU_ASSERT_EQUAL(captured->serial_baud, 9600);
    CU_ASSERT_EQUAL(captured->serial_parity, 'N');
    CU_ASSERT_EQUAL(captured->serial_data_bits, 8);
    CU_ASSERT_EQUAL(captured->serial_stop_bits, 1);
    CU_ASSERT_EQUAL(captured->slave_id, 17); // overridden by gateway
    CU_ASSERT_EQUAL(captured->function, 3);
    CU_ASSERT_EQUAL(captured->register_addr,
                    9); // register number converted later
    CU_ASSERT_EQUAL(captured->format, 1);
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 0);

    free(captured);
    mqtt_test_release_captured_request();
}

void
test_mqtt_format1_no_override(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);
    gateway.slave_id = 0; // allow payload value
    add_serial_filter(&config, "ttyusb0", 12, 4, 0, 65535);

    const char *payload = "1 99 ttyusb0 5 12 4 20 3";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    request_t *captured = mqtt_test_captured_request();
    CU_ASSERT_PTR_NOT_NULL_FATAL(captured);
    CU_ASSERT_EQUAL(captured->slave_id, 12); // payload honored
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 0);

    free(captured);
    mqtt_test_release_captured_request();
}

void
test_mqtt_format1_reject_extra_token(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    gateway.slave_id = 5;

    const char *payload = "1 123 ttyusb0:override 5 9 3 10 2";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_STRING_EQUAL(mqtt_test_last_topic(), "response");
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "123 ERROR: INVALID REQUEST"));
}

void
test_mqtt_format1_missing_write_payload(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);
    add_serial_filter(&config, "ttyusb0", 7, 3, 0, 65535);

    const char *payload = "1 555 ttyusb0 5 7 16 30 2";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "555 ERROR: INVALID REQUEST"));
}

void
test_mqtt_format1_serial_filter_blocks(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    add_serial_filter(&config, "ttyusb0", 5, 3, 0, 5);

    const char *payload = "1 777 ttyusb0 5 5 3 25 2";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "777 ERROR: MESSAGE BLOCKED"));

    filter_free(&config.head);
}

void
test_mqtt_format1_serial_filter_allows(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    add_serial_filter(&config, "ttyusb0", 5, 3, 0, 40);

    const char *payload = "1 888 ttyusb0 5 5 3 25 2";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    request_t *captured = mqtt_test_captured_request();
    CU_ASSERT_PTR_NOT_NULL_FATAL(captured);
    CU_ASSERT_EQUAL(captured->slave_id, 5);
    CU_ASSERT_EQUAL(captured->function, 3);
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 0);

    free(captured);
    mqtt_test_release_captured_request();
    filter_free(&config.head);
}

void
test_mqtt_rejects_invalid_write_values(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    const char *invalid_coil = "1 901 ttyusb0 5 7 15 30 2 0,2";
    struct mosquitto_message msg = make_message(invalid_coil);
    mqtt_message_callback(NULL, &config, &msg);
    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "901 ERROR: INVALID REQUEST"));

    mqtt_test_reset();
    const char *invalid_register = "1 902 ttyusb0 5 7 16 30 2 0,65536";
    msg = make_message(invalid_register);
    mqtt_message_callback(NULL, &config, &msg);
    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "902 ERROR: INVALID REQUEST"));
}

void
test_mqtt_accepts_non_terminated_payload(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);
    add_serial_filter(&config, "ttyusb0", 7, 3, 0, 65535);

    char payload[] = {'1', ' ', '9', '0', '3', ' ', 't', 't',
                      'y', 'u', 's', 'b', '0', ' ', '5', ' ',
                      '7', ' ', '3', ' ', '3', '0', ' ', '2'};
    struct mosquitto_message msg = {
        .payload = payload,
        .payloadlen = (int)sizeof(payload),
        .topic = "request",
    };

    mqtt_message_callback(NULL, &config, &msg);

    request_t *captured = mqtt_test_captured_request();
    CU_ASSERT_PTR_NOT_NULL_FATAL(captured);
    CU_ASSERT_EQUAL(captured->cookie, 903);
    CU_ASSERT_EQUAL(captured->register_addr, 29);
    free(captured);
    mqtt_test_release_captured_request();
}

void
test_mqtt_rejects_invalid_tcp_address(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    const char *payload = "0 904 0 not-an-ip 502 5 7 3 30 2";
    struct mosquitto_message msg = make_message(payload);
    mqtt_message_callback(NULL, &config, &msg);

    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "904 ERROR: INVALID REQUEST"));

    mqtt_test_reset();
    const char *invalid_port = "0 905 0 127.0.0.1 invalid 5 7 3 30 2";
    msg = make_message(invalid_port);
    mqtt_message_callback(NULL, &config, &msg);
    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "905 ERROR: INVALID REQUEST"));
}

void
test_mqtt_rejects_malformed_numeric_fields(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    const char *overflow_address = "1 905 ttyusb0 5 7 3 4294967296 1";
    struct mosquitto_message msg = make_message(overflow_address);
    mqtt_message_callback(NULL, &config, &msg);
    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "905 ERROR: INVALID REQUEST"));

    mqtt_test_reset();
    const char *overflow_cookie = "1 18446744073709551616 ttyusb0 5 7 3 1 1";
    msg = make_message(overflow_cookie);
    mqtt_message_callback(NULL, &config, &msg);
    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "0 ERROR: INVALID REQUEST"));

    mqtt_test_reset();
    const char *trailing_field = "1 906 ttyusb0 5 7 3 1 1 unexpected extra";
    msg = make_message(trailing_field);
    mqtt_message_callback(NULL, &config, &msg);
    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_PTR_NOT_NULL(
        strstr(mqtt_test_last_payload(), "906 ERROR: INVALID REQUEST"));
}

void
test_mqtt_parser_malformed_input_smoke(void) {
    silence_logs();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    unsigned int state = 0x87654321U;
    char payload[96];
    for (size_t iteration = 0; iteration < 256; iteration++) {
        for (size_t i = 0; i < sizeof(payload) - 1; i++) {
            state = state * 1664525U + 1013904223U;
            payload[i] = (char)(32 + (state % 95));
        }
        payload[sizeof(payload) - 1] = '\0';

        mqtt_test_reset();
        struct mosquitto_message msg = {
            .payload = payload,
            .payloadlen = (int)strlen(payload),
            .topic = "request",
        };
        mqtt_message_callback(NULL, &config, &msg);
        request_t *captured = mqtt_test_captured_request();
        free(captured);
        mqtt_test_release_captured_request();
    }
}
