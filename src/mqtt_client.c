/*
 * This file is part of Open Modbus Gateway (omg)
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

    char *buffer = calloc(message->payloadlen + 1, sizeof(char));
    snprintf(buffer, message->payloadlen + 1, "%s", (char *)message->payload);
    buffer[message->payloadlen] = '\0';

    char raw_registers[1024];
    memset(raw_registers, 0, sizeof(raw_registers));

    // Parse the message in a "secure" way
    int num_args =
        sscanf(buffer,
               "%hhu %llu %hhu %63s %7s %hu %hhu %hhu %u %hu %1023s",
               &req->format,        // %d
               &req->cookie,        // %llu
               &req->ip_type,       // %d (Will be managed by modbus_new_tcp_pi)
               (char *)req->ip,     // %63s
               (char *)&req->port,  // %7s
               &req->timeout,       // %d
               &req->slave_id,      // %d
               &req->function,      // %d
               &req->register_addr, // %d (is register number in request format)
               &req->register_count, // %d (is the value if function is 6)
               raw_registers         // %1023s
        );

#ifdef DEBUG
    flog(logfile, "num parameters %i\n", num_args);

    flog(logfile,
         "1: %hhu 2:%llu 3:%hhu 4:%s 5:%s 6:%hu 7:%hhu 8:%hhu 9:%u 10:%hu "
         "11:%s\n",
         req->format,         // %d
         req->cookie,         // %llu
         req->ip_type,        // %d (Will be managed by modbus_new_tcp_pi)
         req->ip,             // %s
         req->port,           // %s (Yes, as string)
         req->timeout,        // %d
         req->slave_id,       // %d
         req->function,       // %d
         req->register_addr,  // %d (is register number in request format)
         req->register_count, // %d (is the value if function is 6)
         raw_registers        // %s
    );
#endif

    // Check the request against the allowed filters
    if (filter_match(config->head, req) != 0) {
        error = MQTT_MESSAGE_BLOCKED;
        flog(logfile, "request blocked {%s}\n", buffer);
        goto cleanup;
    }

    free(buffer);

    switch (num_args) {
    case EILSEQ:
        flog(logfile, "input contains invalid character\n");
        goto cleanup;
    case EINVAL:
        flog(logfile, "not enough arguments\n");
        goto cleanup;
    case ENOMEM:
        flog(logfile, "out of memory\n");
        goto cleanup;
    case ERANGE:
        flog(logfile, "interger size exceeds capacity\n");
        goto cleanup;
    case 10:   // Number of expected items
    case 11:   // or this
        break; // break out of the switch
    default:
        goto cleanup;
    }

    // Track the pointer to mosq
    req->mosq = mosq;

    // Change from Register Number to Register Address
    // Because the request format uses number and libmodbus uses address
    req->register_addr -= 1;

    // Validate inputs
    if (req->format != 0) {
        error = MQTT_INVALID_REQUEST;
        flog(logfile, "invalid format in request\n");
        goto cleanup;
    }
    if (req->ip_type > 2) {
        error = MQTT_INVALID_REQUEST;
        flog(logfile, "invalid IP type in request\n");
        goto cleanup;
    }
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

    // Parsing of register values
    if ((req->function == 15 || req->function == 16) && num_args == 11) {
        int read_count = 0;
        char *token = strtok(raw_registers, ",");

        while (token != NULL) {
            req->data[read_count] = atoi(token);
            token = strtok(NULL, ",");
            read_count++;
        }

        if (read_count != req->register_count) {
            flog(logfile, "invalid number of values supplied\n");
            error = MQTT_INVALID_REQUEST;
            goto cleanup;
        }
    } else if ((req->function == 1 || req->function == 2 ||
                req->function == 3 || req->function == 4 ||
                req->function == 5 || req->function == 6) &&
               num_args == 10) {
        // OK
    } else {
        error = MQTT_INVALID_REQUEST;
        flog(logfile, "invalid protocol arguments\n");
        goto cleanup;
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
