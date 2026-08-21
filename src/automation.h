#ifndef AUTOMATION_H
#define AUTOMATION_H

#include <stddef.h>

#include "config_parser.h"
#include "request.h"

int automation_init(const char *script_path);
void automation_set_config(const config_t *config);
void automation_shutdown(void);
int automation_emit_gateway_started(void);
int automation_emit_gateway_stopping(void);
int automation_emit_mqtt_connected(void);
int automation_emit_mqtt_disconnected(const char *reason);
int automation_emit_request_accepted(const request_t *request);
int automation_emit_request_rejected(unsigned long long cookie, int error);
int automation_intercept_request(const config_t *config,
                                 request_t *request,
                                 char *reason,
                                 size_t reason_size);
int automation_transform_response(request_t *request);
void automation_queue_modbus_result(const request_t *request,
                                    int succeeded,
                                    const char *reason);
int automation_dispatch_pending(void);
int automation_emit_timer(void);

#endif
