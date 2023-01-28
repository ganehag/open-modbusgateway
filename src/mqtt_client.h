#ifndef MQTT_CLIENT_H
#define MQTT_CLIENT_H

#include <mosquitto.h>
#include <stdint.h>

#define MQTT_INVALID_REQUEST 1
#define MQTT_ERROR_MESSAGE 2
#define MQTT_MESSAGE_BLOCKED 3

void mqtt_reply_error(struct mosquitto *mosq,
                      const char *topic,
                      uint64_t cookie,
                      int error,
                      const char *str_msg);
void mqtt_reply_ok(struct mosquitto *mosq,
                   const char *topic,
                   uint64_t cookie,
                   uint32_t datalen,
                   uint16_t *data);
void mqtt_stderr_log(int rc);
void mqtt_connect_callback(struct mosquitto *mosq, void *obj, int result);
void mqtt_message_callback(struct mosquitto *mosq,
                           void *obj,
                           const struct mosquitto_message *message);

#endif
