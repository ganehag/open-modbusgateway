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

#include "automation.h"
#include "log.h"
#include "mqtt_client.h"
#include "request.h"

uint16_t request_count = 0;
pthread_mutex_t request_count_mutex = PTHREAD_MUTEX_INITIALIZER;

int
request_thread_reserve(void) {
    int reserved = 0;

    pthread_mutex_lock(&request_count_mutex);
    if (request_count < MAX_REQUEST_THREADS) {
        request_count++;
        reserved = 1;
    }
    pthread_mutex_unlock(&request_count_mutex);

    return reserved;
}

void
request_thread_release(void) {
    pthread_mutex_lock(&request_count_mutex);
    if (request_count > 0) {
        request_count--;
    }
    pthread_mutex_unlock(&request_count_mutex);
}

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
    int succeeded = 0;
    char failure_reason[128] = "request failed";

    pthread_detach(pthread_self());

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
        snprintf(failure_reason,
                 sizeof(failure_reason),
                 "%s",
                 modbus_strerror(errno));
        goto modbus_cleanup;
    }

    modbus_set_response_timeout(ctx, req->timeout, 0);
    modbus_set_slave(ctx, req->slave_id);
    if (modbus_connect(ctx) == -1) {
        snprintf(failure_reason,
                 sizeof(failure_reason),
                 "%s",
                 modbus_strerror(errno));
        goto modbus_cleanup;
    }

    uint8_t coil_data[125];
    int result = -1;
    switch (req->function) {
    case 1:
        result = modbus_read_bits(
            ctx, req->register_addr, req->register_count, coil_data);
        for (int i = 0; result != -1 && i < req->register_count; i++)
            req->data[i] = coil_data[i];
        break;
    case 2:
        result = modbus_read_input_bits(
            ctx, req->register_addr, req->register_count, coil_data);
        for (int i = 0; result != -1 && i < req->register_count; i++)
            req->data[i] = coil_data[i];
        break;
    case 3:
        result = modbus_read_registers(
            ctx, req->register_addr, req->register_count, req->data);
        break;
    case 4:
        result = modbus_read_input_registers(
            ctx, req->register_addr, req->register_count, req->data);
        break;
    case 5:
        result = modbus_write_bit(
            ctx, req->register_addr, req->register_count > 0 ? TRUE : FALSE);
        break;
    case 6:
        result =
            modbus_write_register(ctx, req->register_addr, req->register_count);
        break;
    case 15:
        for (int i = 0; i < req->register_count; i++)
            coil_data[i] = req->data[i] > 0 ? TRUE : FALSE;
        result = modbus_write_bits(
            ctx, req->register_addr, req->register_count, coil_data);
        break;
    case 16:
        result = modbus_write_registers(
            ctx, req->register_addr, req->register_count, req->data);
        break;
    default:
        snprintf(
            failure_reason, sizeof(failure_reason), "invalid Modbus function");
        goto modbus_cleanup;
    }
    if (result == -1) {
        snprintf(failure_reason,
                 sizeof(failure_reason),
                 "%s",
                 modbus_strerror(errno));
        goto modbus_cleanup;
    }
    succeeded = 1;

modbus_cleanup:
    automation_queue_modbus_result(req, succeeded, failure_reason);

    // Modbus clean-up
    if (ctx != NULL) {
        modbus_close(ctx);
        modbus_free(ctx);
    }

    free(req);

    request_thread_release();

    pthread_exit(NULL);
}
