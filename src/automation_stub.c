#include <stdio.h>

#include "automation.h"
#include "mqtt_client.h"

int
automation_init(const char *script_path) {
    if (script_path != NULL && script_path[0] != '\0') {
        fprintf(stderr,
                "Lua automation is disabled; rebuild with --enable-lua to use "
                "a script\n");
        return -1;
    }
    return 0;
}

void
automation_set_config(const config_t *config) {
    (void)config;
}

void
automation_shutdown(void) {}

int
automation_emit_gateway_started(void) {
    return 0;
}

int
automation_emit_gateway_stopping(void) {
    return 0;
}

int
automation_emit_mqtt_connected(void) {
    return 0;
}

int
automation_emit_mqtt_disconnected(const char *reason) {
    (void)reason;
    return 0;
}

int
automation_emit_request_accepted(const request_t *request) {
    (void)request;
    return 0;
}

int
automation_emit_request_rejected(unsigned long long cookie, int error) {
    (void)cookie;
    (void)error;
    return 0;
}

int
automation_intercept_request(const config_t *config,
                             request_t *request,
                             char *reason,
                             size_t reason_size) {
    (void)config;
    (void)request;
    (void)reason;
    (void)reason_size;
    return 0;
}

int
automation_transform_response(request_t *request) {
    (void)request;
    return 0;
}

void
automation_queue_modbus_result(const request_t *request,
                               int succeeded,
                               const char *reason) {
    if (request == NULL) {
        return;
    }
    if (succeeded) {
        uint32_t data_length =
            request->function <= 4 ? request->register_count : 0;
        mqtt_reply_ok(request->mosq,
                      request->response_topic,
                      request->cookie,
                      data_length,
                      request->data,
                      request->response_qos,
                      request->response_retain);
    } else {
        mqtt_reply_error(request->mosq,
                         request->response_topic,
                         request->cookie,
                         MQTT_ERROR_MESSAGE,
                         reason,
                         request->response_qos,
                         request->response_retain);
    }
}

int
automation_dispatch_pending(void) {
    return 0;
}

int
automation_emit_timer(void) {
    return 0;
}
