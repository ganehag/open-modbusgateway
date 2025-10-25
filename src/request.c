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
#include <modbus/modbus.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "mqtt_client.h"
#include "request.h"

uint16_t request_count = 0;
pthread_mutex_t request_count_mutex = PTHREAD_MUTEX_INITIALIZER;

char *
join_regs_str(const uint16_t datalen, const uint16_t *data, const char *sep) {
    char *joined = NULL;
    size_t lensep = strlen(sep); // separator length
    size_t sz = 0;               // current size
    uint8_t is_first = true;
    char buff[12];

    for (int i = 0; i < datalen; i++) {
        memset(buff, 0, sizeof(buff));
        snprintf(buff, sizeof(buff), "%d", data[i]);
        size_t len = strlen(buff);

        // allocate/reallocate joined
        void *tmp =
            realloc(joined, sz + len + (is_first == true ? 0 : lensep) + 1);
        if (!tmp) {
            // Allocation error
            return NULL;
        }

        joined = tmp;
        if (is_first == false) {
            strcpy(joined + sz, sep);
            sz += lensep;
        }

        strcpy(joined + sz, buff);
        is_first = false;
        sz += len;
    }

    return joined;
}

void *
handle_request(void *arg) {
    modbus_t *ctx = NULL;
    request_t *req = (request_t *)arg;
    uint16_t req_count;

    pthread_mutex_lock(&request_count_mutex);
    request_count++;
    req_count = request_count;
    pthread_mutex_unlock(&request_count_mutex);

    // debug print request after cast

#ifdef DEBUG
    flog(logfile, "void *handle_request(void *arg)\n");
    if (req->format == 1) {
        flog(logfile,
             "format 1: %hhu %llu %s %s %d-%c-%d-%d %hu %hhu %u %hu\n",
             req->format,
             req->cookie,
             req->serial_id,
             req->serial_device,
             req->serial_baud,
             req->serial_parity,
             req->serial_data_bits,
             req->serial_stop_bits,
             req->timeout,
             req->slave_id,
             req->register_addr,
             req->register_count);
    } else {
        flog(logfile,
             "format 0: %hhu %llu %hhu %s %s %hu %hhu %u %hu\n",
             req->format,
             req->cookie,
             req->ip_type,
             req->ip,
             req->port,
             req->timeout,
             req->slave_id,
             req->register_addr,
             req->register_count);
    }
#endif

    // Detach from the parent thread (join not required)
    pthread_detach(pthread_self());

    if (req_count > MAX_REQUEST_THREADS) {
        mqtt_reply_error(req->mosq,
                         req->response_topic,
                         req->cookie,
                         MQTT_ERROR_MESSAGE,
                         "Too many requests");
        goto pthread_exit;
    }

    if (req->format == 1) {
        ctx = modbus_new_rtu(req->serial_device,
                             req->serial_baud,
                             req->serial_parity,
                             req->serial_data_bits,
                             req->serial_stop_bits);
    } else {
        ctx = modbus_new_tcp_pi(req->ip, req->port);
    }

    if (ctx == NULL) {
        mqtt_reply_error(req->mosq,
                         req->response_topic,
                         req->cookie,
                         MQTT_ERROR_MESSAGE,
                         modbus_strerror(errno));
        goto modbus_cleanup;
    }

    // Set the timeout
    modbus_set_response_timeout(ctx, req->timeout, 0);

    // Set the slave id
    modbus_set_slave(ctx, req->slave_id);

    // Perform a connect
    if (modbus_connect(ctx) == -1) {
        mqtt_reply_error(req->mosq,
                         req->response_topic,
                         req->cookie,
                         MQTT_ERROR_MESSAGE,
                         modbus_strerror(errno));
        goto modbus_cleanup;
    } else {
        uint8_t coil_data[123];

        switch (req->function) {
        case 1: // Read coils
            if (modbus_read_bits(
                    ctx, req->register_addr, req->register_count, coil_data) ==
                -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }
            for (int i = 0; i < req->register_count; i++) {
                req->data[i] = coil_data[i];
            }

            mqtt_reply_ok(req->mosq,
                          req->response_topic,
                          req->cookie,
                          req->register_count,
                          req->data);
            break;
        case 2: // Read discrete inputs
            if (modbus_read_input_bits(
                    ctx, req->register_addr, req->register_count, coil_data) ==
                -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }
            for (int i = 0; i < req->register_count; i++) {
                req->data[i] = coil_data[i];
            }

            mqtt_reply_ok(req->mosq,
                          req->response_topic,
                          req->cookie,
                          req->register_count,
                          req->data);
            break;
        case 3: // Read holding register
            if (modbus_read_registers(
                    ctx, req->register_addr, req->register_count, req->data) ==
                -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }

            mqtt_reply_ok(req->mosq,
                          req->response_topic,
                          req->cookie,
                          req->register_count,
                          req->data);
            break;
        case 4: // Read input register
            if (modbus_read_input_registers(
                    ctx, req->register_addr, req->register_count, req->data) ==
                -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }

            mqtt_reply_ok(req->mosq,
                          req->response_topic,
                          req->cookie,
                          req->register_count,
                          req->data);
            break;
        case 5: // Function code 5 (force/write single coil)
            if (req->register_count > 0) {
                coil_data[0] = TRUE;
            } else {
                coil_data[0] = FALSE;
            }

            if (modbus_write_bit(ctx, req->register_addr, coil_data[0]) == -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }

            mqtt_reply_ok(req->mosq, req->response_topic, req->cookie, 0, NULL);
            break;
        case 6: // Write single holding register
            if (modbus_write_register(
                    ctx, req->register_addr, req->register_count) == -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }

            mqtt_reply_ok(req->mosq, req->response_topic, req->cookie, 0, NULL);
            break;
        case 15: // Function code 15 (force/write multiple coils)
            for (int i = 0; i < req->register_count; i++) {
                coil_data[i] = (req->data[i] > 0) ? TRUE : FALSE;
            }
            if (modbus_write_bits(
                    ctx, req->register_addr, req->register_count, coil_data) ==
                -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }

            mqtt_reply_ok(req->mosq, req->response_topic, req->cookie, 0, NULL);
            break;
        case 16: // write multiple holding registers
            if (modbus_write_registers(
                    ctx, req->register_addr, req->register_count, req->data) ==
                -1) {
                mqtt_reply_error(req->mosq,
                                 req->response_topic,
                                 req->cookie,
                                 MQTT_ERROR_MESSAGE,
                                 modbus_strerror(errno));
                goto modbus_cleanup;
            }

            mqtt_reply_ok(req->mosq, req->response_topic, req->cookie, 0, NULL);
            break;
        default:
            mqtt_reply_error(req->mosq,
                             req->response_topic,
                             req->cookie,
                             MQTT_INVALID_REQUEST,
                             NULL);
            goto modbus_cleanup;
            break;
        }

#ifdef DEBUG

        if (req->function >= 1 && req->function <= 4) {
            for (int i = 0; i < req->register_count; i++) {
                fprintf(logfile,
                        "data[%d] = %d (0x%X)\n",
                        i,
                        req->data[i],
                        req->data[i]);
            }
        }
#endif
    }

modbus_cleanup:

    // Modbus clean-up
    if (ctx != NULL) {
        modbus_close(ctx);
        modbus_free(ctx);
    }

    // Must free the allocated argument
    free(req);

pthread_exit:

    // decrement the number of concurrent threads
    pthread_mutex_lock(&request_count_mutex);
    request_count--;
    pthread_mutex_unlock(&request_count_mutex);

    pthread_exit(NULL);
}
