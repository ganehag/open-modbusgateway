#include "mqtt_test_helpers.h"

#include <mosquitto.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/mqtt_client.h"
#include "../src/request.h"

static int publish_count = 0;
static char last_topic[256];
static char last_payload[1024];
static int last_rc = MOSQ_ERR_SUCCESS;

static request_t *captured_request = NULL;

void
mqtt_test_reset(void) {
    publish_count = 0;
    memset(last_topic, 0, sizeof(last_topic));
    memset(last_payload, 0, sizeof(last_payload));
    last_rc = MOSQ_ERR_SUCCESS;
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
    (void)qos;
    return MOSQ_ERR_SUCCESS;
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
    (void)qos;
    (void)retain;

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

    if (thread != NULL) {
        memset(thread, 0, sizeof(*thread));
    }

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

    size_t max_len =
        datalen * (sizeof(buff) + lensep) + 1; // rough upper bound
    char *joined = calloc(max_len, sizeof(char));
    if (joined == NULL) {
        return NULL;
    }

    for (uint16_t i = 0; i < datalen; i++) {
        if (!is_first) {
            strncpy(joined + sz, sep, lensep);
            sz += lensep;
        }

        snprintf(buff, sizeof(buff), "%u", data[i]);
        size_t len = strlen(buff);
        strncpy(joined + sz, buff, len);
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
