/*
 * This file is part of Open MQTT Modbus Gateway (ommg)
 * https://github.com/ganehag/open-modbusgateway.
 *
 * Copyright (c) 2023 Mikael Ganehag Brorsson.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <mosquitto.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config_parser.h"
#include "filters.h"
#include "log.h"
#include "mqtt_client.h"

void
mqtt_message_callback(struct mosquitto *mosq,
                      void *obj,
                      const struct mosquitto_message *message) {

    // obj is config_t
    config_t *config = (config_t *)obj;

    int error = 0;
    pthread_t ptid;
    request_t *req = calloc(1, sizeof(request_t));
    char *buffer = NULL;
    int num_args = 0;
    int min_args = 0;
    int max_args = 0;
    bool has_value_block = false;

    if (req == NULL) {
        // Allocation failure means we cannot proceed or report meaningfully
        return;
    }

    buffer = calloc(message->payloadlen + 1, sizeof(char));
    if (buffer == NULL) {
        error = MQTT_ERROR_MESSAGE;
        goto cleanup;
    }

    snprintf(buffer, message->payloadlen + 1, "%s", (char *)message->payload);
    buffer[message->payloadlen] = '\0';

    char raw_registers[1024];
    memset(raw_registers, 0, sizeof(raw_registers));

    char serial_token[sizeof(req->serial_id)];
    memset(serial_token, 0, sizeof(serial_token));

    if (sscanf(buffer, "%hhu", &req->format) != 1) {
        error = MQTT_INVALID_REQUEST;
        goto cleanup;
    }

    switch (req->format) {
    case 0:
        num_args = sscanf(buffer,
                          "%hhu %llu %hhu %63s %7s %hu %hhu %hhu %u %hu %1023s",
                          &req->format,
                          &req->cookie,
                          &req->ip_type,
                          (char *)req->ip,
                          (char *)&req->port,
                          &req->timeout,
                          &req->slave_id,
                          &req->function,
                          &req->register_addr,
                          &req->register_count,
                          raw_registers);
        min_args = 10;
        max_args = 11;
        break;
    case 1:
        num_args = sscanf(buffer,
                          "%hhu %llu %63s %hu %hhu %hhu %u %hu %1023s",
                          &req->format,
                          &req->cookie,
                          serial_token,
                          &req->timeout,
                          &req->slave_id,
                          &req->function,
                          &req->register_addr,
                          &req->register_count,
                          raw_registers);
        min_args = 8;
        max_args = 9;
        break;
    default:
        error = MQTT_INVALID_REQUEST;
        goto cleanup;
    }

    if (num_args < min_args) {
        error = MQTT_INVALID_REQUEST;
        goto cleanup;
    }

    if (num_args != min_args && num_args != max_args) {
        error = MQTT_INVALID_REQUEST;
        goto cleanup;
    }

    has_value_block = (num_args == max_args);

#ifdef DEBUG
    if (req->format == 0) {
        flog(logfile,
             "format 0 parsed: %hhu %llu %hhu %s %s %hu %hhu %hhu %u %hu %s\n",
             req->format,
             req->cookie,
             req->ip_type,
             req->ip,
             req->port,
             req->timeout,
             req->slave_id,
             req->function,
             req->register_addr,
             req->register_count,
             raw_registers);
    } else {
        flog(logfile,
             "format 1 parsed: %hhu %llu %s %hu %hhu %hhu %u %hu %s\n",
             req->format,
             req->cookie,
             serial_token,
             req->timeout,
             req->slave_id,
             req->function,
             req->register_addr,
             req->register_count,
             raw_registers);
    }
#endif

    if (req->format == 0) {
        if (filter_match(config->head, req) != 0) {
            error = MQTT_MESSAGE_BLOCKED;
            flog(logfile, "request blocked {%s}\n", buffer);
            goto cleanup;
        }
    }

    if (req->format == 1) {
        if (serial_token[0] == '\0') {
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }

        char serial_copy[sizeof(serial_token)];
        strncpy(serial_copy, serial_token, sizeof(serial_copy));
        serial_copy[sizeof(serial_copy) - 1] = '\0';

        char *saveptr = NULL;
        char *token = strtok_r(serial_copy, ":", &saveptr);
        if (token == NULL || token[0] == '\0') {
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }

        strncpy(req->serial_id, token, sizeof(req->serial_id));
        req->serial_id[sizeof(req->serial_id) - 1] = '\0';

        serial_gateway_t *gateway =
            serial_gateway_find(config->serial_head, req->serial_id);

        if (gateway == NULL) {
            flog(logfile, "unknown serial gateway id '%s'\n", req->serial_id);
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }

        strncpy(
            req->serial_device, gateway->device, sizeof(req->serial_device));
        req->serial_device[sizeof(req->serial_device) - 1] = '\0';
        req->serial_baud = gateway->baudrate;
        req->serial_parity = gateway->parity;
        req->serial_data_bits = gateway->data_bits;
        req->serial_stop_bits = gateway->stop_bits;

        if (gateway->slave_id > 0) {
            req->slave_id = gateway->slave_id;
        }

        token = strtok_r(NULL, ":", &saveptr);
        if (token != NULL && token[0] != '\0') {
            flog(logfile,
                 "unexpected serial override for gateway id '%s'\n",
                 req->serial_id);
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }
    }

    // Track the pointer to mosq
    req->mosq = mosq;

    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
    }

    if (req->register_addr == 0) {
        error = MQTT_INVALID_REQUEST;
        goto cleanup;
    }

    // Change from Register Number to Register Address
    // Because the request format uses number and libmodbus uses address
    req->register_addr -= 1;

    // Validate inputs common to both formats
    if (req->function != 1 && req->function != 2 && req->function != 3 &&
        req->function != 4 && req->function != 5 && req->function != 6 &&
        req->function != 15 && req->function != 16) {
        error = MQTT_INVALID_REQUEST;
        flog(logfile, "invalid function call in request\n");
        goto cleanup;
    }

    if ((req->function == 15 || req->function == 16) &&
        req->register_count > 123) {
        error = MQTT_INVALID_REQUEST;
        flog(logfile, "overflow register count in request\n");
        goto cleanup;
    }

    if (req->format == 0 && req->ip_type > 2) {
        error = MQTT_INVALID_REQUEST;
        flog(logfile, "invalid IP type in request\n");
        goto cleanup;
    }

    // Parsing of register values
    if (req->function == 15 || req->function == 16) {
        if (!has_value_block) {
            flog(logfile, "missing register payload for write request\n");
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }

        int read_count = 0;
        char *token = strtok(raw_registers, ",");

        while (token != NULL && read_count < 123) {
            req->data[read_count] = atoi(token);
            token = strtok(NULL, ",");
            read_count++;
        }

        if (read_count != req->register_count) {
            flog(logfile, "invalid number of values supplied\n");
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }
    } else {
        if (has_value_block && req->format == 0) {
            // format 0 includes a trailing values block only for writes
            error = MQTT_INVALID_REQUEST;
            flog(logfile, "unexpected payload for read request\n");
            goto cleanup;
        }
        if (has_value_block && req->format == 1) {
            error = MQTT_INVALID_REQUEST;
            flog(logfile, "unexpected payload for read request\n");
            goto cleanup;
        }
    }

    // copy request_topic from config to request
    memset(req->response_topic, 0, sizeof(req->response_topic));
    strncpy(req->response_topic,
            config->response_topic,
            sizeof(req->response_topic));

    // Run the handler as a separate thread
    pthread_create(&ptid, NULL, &handle_request, req);

    goto done;

cleanup:
    if (buffer != NULL) {
        free(buffer);
        buffer = NULL;
    }

    mqtt_reply_error(mosq, config->response_topic, req->cookie, error, NULL);

    // If something failed along the way
    free(req);

done:
    return;
}

void
mqtt_connect_callback(struct mosquitto *mosq, void *obj, int result) {
    config_t *config = (config_t *)obj;

    mosquitto_subscribe(mosq, NULL, config->request_topic, 0);
}

void
mqtt_logfile_log(int rc) {
    switch (rc) {
    case MOSQ_ERR_SUCCESS:
        return;
        break;
    case MOSQ_ERR_INVAL:
        fprintf(logfile, "invalid input parameters\n");
        break;
    case MOSQ_ERR_NOMEM:
        fprintf(logfile, "out of memory\n");
        break;
    case MOSQ_ERR_NO_CONN:
        fprintf(logfile, "not connected to broker\n");
        break;
    case MOSQ_ERR_PROTOCOL:
        fprintf(logfile, "protocol error while communicating with broker\n");
        break;
    case MOSQ_ERR_PAYLOAD_SIZE:
        fprintf(logfile, "payload is too large\n");
        break;
        /*
                case MOSQ_ERR_MALFORMED_UTF8:
                    fprintf(logfile, "malformed reply topic\n");
                break;
        */
    default:
        fprintf(logfile, "unknown error while publishing to broker\n");
        break;
    }
}

void
mqtt_reply_error(struct mosquitto *mosq,
                 const char *topic,
                 unsigned long long int cookie,
                 int error,
                 const char *str_msg) {
    char error_msg[256];
    memset(error_msg, 0, sizeof(error_msg));

    switch (error) {
    case MQTT_INVALID_REQUEST:
        snprintf(error_msg,
                 sizeof(error_msg),
                 "%llu ERROR: INVALID REQUEST",
                 cookie);
        break;
    case MQTT_MESSAGE_BLOCKED:
        snprintf(error_msg,
                 sizeof(error_msg),
                 "%llu ERROR: MESSAGE BLOCKED",
                 cookie);
        break;
    case MQTT_ERROR_MESSAGE:
        snprintf(
            error_msg, sizeof(error_msg), "%llu ERROR: %s", cookie, str_msg);
        break;
    default:
        snprintf(error_msg, sizeof(error_msg), "%llu ERROR: UNKNOWN", cookie);
        break;
    }

    int rc = mosquitto_publish(
        mosq, NULL, topic, strlen(error_msg), error_msg, 1, false);
    mqtt_logfile_log(rc);
}

void
mqtt_reply_ok(struct mosquitto *mosq,
              const char *topic,
              unsigned long long int cookie,
              uint32_t datalen,
              uint16_t *data) {
    char msg[1024];
    memset(msg, 0, sizeof(msg));

    if (datalen > 0) {
        char *data_str = join_regs_str(datalen, data, " ");
        snprintf(msg, sizeof(msg), "%llu OK %s", cookie, data_str);
        free(data_str);
    } else {
        snprintf(msg, sizeof(msg), "%llu OK", cookie);
    }

    int rc = mosquitto_publish(mosq, NULL, topic, strlen(msg), msg, 1, false);
    mqtt_logfile_log(rc);
}
