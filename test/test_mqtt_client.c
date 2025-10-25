#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/config_parser.h"
#include "../src/log.h"
#include "../src/mqtt_client.h"
#include "../src/request.h"
#include "../src/filters.h"
#include "mqtt_test_helpers.h"
#include "test.h"

extern FILE *logfile;

static void
silence_logs(void) {
    set_logfile("/dev/null");
}

static void
setup_basic_config(config_t *config, serial_gateway_t *gateway) {
    memset(config, 0, sizeof(*config));
    memset(gateway, 0, sizeof(*gateway));

    strncpy(config->response_topic, "response", sizeof(config->response_topic) - 1);
    config->serial_head = gateway;
    config->head = NULL;

    strncpy(gateway->id, "ttyusb0", sizeof(gateway->id) - 1);
    strncpy(gateway->device, "/dev/ttyUSB0", sizeof(gateway->device) - 1);
    gateway->baudrate = 9600;
    gateway->parity = 'N';
    gateway->data_bits = 8;
    gateway->stop_bits = 1;
    gateway->next = NULL;
}

static void
add_serial_filter(config_t *config,
                  const char *serial_id,
                  uint8_t slave_id,
                  uint8_t function,
                  uint16_t reg_min,
                  uint16_t reg_max) {
    filter_t *filter = calloc(1, sizeof(filter_t));
    filter->applies_serial = 1;
    if (serial_id != NULL) {
        strncpy(filter->serial_id, serial_id, sizeof(filter->serial_id) - 1);
    }
    filter->slave_id = slave_id;
    filter->function_code = function;
    filter->register_address_min = reg_min;
    filter->register_address_max = reg_max;
    filter_add(&config->head, filter);
}

static struct mosquitto_message
make_message(const char *payload) {
    struct mosquitto_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.payload = (void *)payload;
    msg.payloadlen = (int)strlen(payload);
    msg.topic = "request";
    return msg;
}

void
test_mqtt_format1_slave_override(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);
    gateway.slave_id = 17;

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
    CU_ASSERT_EQUAL(captured->register_addr, 9); // register number converted later
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
    CU_ASSERT_PTR_NOT_NULL(strstr(mqtt_test_last_payload(), "123 ERROR: INVALID REQUEST"));
}

void
test_mqtt_format1_missing_write_payload(void) {
    silence_logs();
    mqtt_test_reset();

    config_t config;
    serial_gateway_t gateway;
    setup_basic_config(&config, &gateway);

    const char *payload = "1 555 ttyusb0 5 7 16 30 2";
    struct mosquitto_message msg = make_message(payload);

    mqtt_message_callback(NULL, &config, &msg);

    CU_ASSERT_PTR_NULL(mqtt_test_captured_request());
    CU_ASSERT_EQUAL(mqtt_test_publish_count(), 1);
    CU_ASSERT_PTR_NOT_NULL(strstr(mqtt_test_last_payload(), "555 ERROR: INVALID REQUEST"));
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
    CU_ASSERT_PTR_NOT_NULL(strstr(mqtt_test_last_payload(), "777 ERROR: MESSAGE BLOCKED"));

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
