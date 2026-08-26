#ifndef MQTT_TEST_HELPERS_H
#define MQTT_TEST_HELPERS_H

#include <stddef.h>

#include <mosquitto.h>

#include "../src/config_parser.h"
#include "../src/request.h"

void mqtt_test_reset(void);

int mqtt_test_publish_count(void);
const char *mqtt_test_last_topic(void);
const char *mqtt_test_last_payload(void);
int mqtt_test_last_rc(void);

request_t *mqtt_test_captured_request(void);
void mqtt_test_release_captured_request(void);
void mqtt_test_silence_logs(void);
void mqtt_test_setup_serial_config(config_t *config, serial_gateway_t *gateway);
void mqtt_test_add_serial_filter(config_t *config,
                                 const char *serial_id,
                                 uint8_t slave_id,
                                 uint8_t function,
                                 uint16_t reg_min,
                                 uint16_t reg_max);
struct mosquitto_message mqtt_test_make_message(const char *payload);

#endif
