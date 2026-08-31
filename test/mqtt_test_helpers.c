#include "mqtt_test_helpers.h"

#include <mosquitto.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/filters.h"
#include "../src/log.h"
#include "../src/mqtt_client.h"
#include "../src/request.h"

static int publish_count = 0;
static char last_topic[256];
static char last_payload[1024];
static int last_rc = MOSQ_ERR_SUCCESS;
static int last_qos = -1;
static bool last_retain = false;
static int last_subscribe_qos = -1;
static int subscribe_result = MOSQ_ERR_SUCCESS;
static int disconnect_count = 0;

static request_t *captured_request = NULL;

void
mqtt_test_silence_logs(void) {
    set_logfile("/dev/null");
}

void
mqtt_test_setup_serial_config(config_t *config, serial_gateway_t *gateway) {
    memset(config, 0, sizeof(*config));
    memset(gateway, 0, sizeof(*gateway));

    strncpy(
        config->response_topic, "response", sizeof(config->response_topic) - 1);
    config->serial_head = gateway;
    strncpy(gateway->id, "ttyusb0", sizeof(gateway->id) - 1);
    strncpy(gateway->device, "/dev/ttyUSB0", sizeof(gateway->device) - 1);
    gateway->baudrate = 9600;
    gateway->parity = 'N';
    gateway->data_bits = 8;
    gateway->stop_bits = 1;
}

void
mqtt_test_add_serial_filter(config_t *config,
                            const char *serial_id,
                            uint8_t slave_id,
                            uint8_t function,
                            uint16_t reg_min,
                            uint16_t reg_max) {
    filter_t *filter = calloc(1, sizeof(*filter));
    if (filter == NULL) {
        return;
    }
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

struct mosquitto_message
mqtt_test_make_message(const char *payload) {
    struct mosquitto_message message = {0};
    message.payload = (void *)payload;
    message.payloadlen = (int)strlen(payload);
    message.topic = "request";
    return message;
}

int
request_thread_reserve(void) {
    return 1;
}

void
request_thread_release(void) {}

void
request_transport_lock(const request_t *request) {
    (void)request;
}

void
request_transport_unlock(const request_t *request) {
    (void)request;
}

int
request_validate_modbus(const request_t *request, int one_based_address) {
    if (request == NULL || request->timeout == 0 || request->slave_id == 0 ||
        (one_based_address && request->register_addr == 0)) {
        return -1;
    }
    return 0;
}

void
mqtt_test_reset(void) {
    publish_count = 0;
    memset(last_topic, 0, sizeof(last_topic));
    memset(last_payload, 0, sizeof(last_payload));
    last_rc = MOSQ_ERR_SUCCESS;
    last_qos = -1;
    last_retain = false;
    last_subscribe_qos = -1;
    subscribe_result = MOSQ_ERR_SUCCESS;
    disconnect_count = 0;
    captured_request = NULL;
}

int
mqtt_test_publish_count(void) {
    return publish_count;
}

const char *
mqtt_test_last_topic(void) {
    return last_topic;
}

const char *
mqtt_test_last_payload(void) {
    return last_payload;
}

int
mqtt_test_last_rc(void) {
    return last_rc;
}

int
mqtt_test_last_qos(void) {
    return last_qos;
}

bool
mqtt_test_last_retain(void) {
    return last_retain;
}

int
mqtt_test_last_subscribe_qos(void) {
    return last_subscribe_qos;
}

void
mqtt_test_set_subscribe_result(int result) {
    subscribe_result = result;
}

int
mqtt_test_disconnect_count(void) {
    return disconnect_count;
}

request_t *
mqtt_test_captured_request(void) {
    return captured_request;
}

void
mqtt_test_release_captured_request(void) {
    captured_request = NULL;
}

int
mosquitto_subscribe(struct mosquitto *mosq,
                    int *mid,
                    const char *sub,
                    int qos) {
    (void)mosq;
    (void)mid;
    (void)sub;
    last_subscribe_qos = qos;
    return subscribe_result;
}

int
mosquitto_disconnect(struct mosquitto *mosq) {
    (void)mosq;
    disconnect_count++;
    return MOSQ_ERR_SUCCESS;
}

const char *
mosquitto_strerror(int mosq_errno) {
    (void)mosq_errno;
    return "mock MQTT error";
}

const char *
mosquitto_connack_string(int connack_code) {
    (void)connack_code;
    return "mock connection rejected";
}

int
mosquitto_publish(struct mosquitto *mosq,
                  int *mid,
                  const char *topic,
                  int payloadlen,
                  const void *payload,
                  int qos,
                  bool retain) {
    (void)mosq;
    (void)mid;
    last_qos = qos;
    last_retain = retain;

    publish_count++;
    if (topic != NULL) {
        strncpy(last_topic, topic, sizeof(last_topic) - 1);
        last_topic[sizeof(last_topic) - 1] = '\0';
    }

    if (payload != NULL) {
        size_t copy_len = (payloadlen < (int)sizeof(last_payload) - 1)
                              ? (size_t)payloadlen
                              : sizeof(last_payload) - 1;
        memcpy(last_payload, payload, copy_len);
        last_payload[copy_len] = '\0';
    } else {
        last_payload[0] = '\0';
    }

    last_rc = MOSQ_ERR_SUCCESS;
    return MOSQ_ERR_SUCCESS;
}

int
pthread_create(pthread_t *thread,
               const pthread_attr_t *attr,
               void *(*start_routine)(void *),
               void *arg) {
    (void)attr;

    memset(thread, 0, sizeof(*thread));

    captured_request = (request_t *)arg;
    (void)start_routine;
    return 0;
}

char *
join_regs_str(const uint16_t datalen, const uint16_t *data, const char *sep) {
    if (datalen == 0 || data == NULL || sep == NULL) {
        return NULL;
    }

    size_t lensep = strlen(sep);
    size_t sz = 0;
    uint8_t is_first = true;
    char buff[12];

    size_t max_len = datalen * (sizeof(buff) + lensep) + 1; // rough upper bound
    char *joined = calloc(max_len, sizeof(char));
    if (joined == NULL) {
        return NULL;
    }

    for (uint16_t i = 0; i < datalen; i++) {
        if (!is_first) {
            memcpy(joined + sz, sep, lensep);
            sz += lensep;
        }

        snprintf(buff, sizeof(buff), "%u", data[i]);
        size_t len = strlen(buff);
        memcpy(joined + sz, buff, len);
        sz += len;
        is_first = false;
    }

    joined[sz] = '\0';
    return joined;
}

void *
handle_request(void *arg) {
    if (arg != NULL) {
        free(arg);
    }
    return NULL;
}
