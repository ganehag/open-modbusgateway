#ifndef MQTT_TEST_HELPERS_H
#define MQTT_TEST_HELPERS_H

#include <stddef.h>

#include "../src/request.h"

void mqtt_test_reset(void);

int mqtt_test_publish_count(void);
const char *mqtt_test_last_topic(void);
const char *mqtt_test_last_payload(void);
int mqtt_test_last_rc(void);

request_t *mqtt_test_captured_request(void);
void mqtt_test_release_captured_request(void);

#endif
