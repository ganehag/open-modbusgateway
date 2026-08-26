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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <modbus/modbus.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "automation.h"
#include "log.h"
#include "mqtt_client.h"
#include "request.h"

uint16_t request_count = 0;
static unsigned int request_limit = DEFAULT_MAX_INFLIGHT_REQUESTS;
pthread_mutex_t request_count_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t request_count_cond = PTHREAD_COND_INITIALIZER;

#define SERIAL_TRANSPORT_LOCKS 32

static pthread_mutex_t serial_transport_locks[SERIAL_TRANSPORT_LOCKS];
static pthread_once_t serial_transport_locks_once = PTHREAD_ONCE_INIT;

static modbus_t *
request_modbus_new_rtu(const request_t *request) {
#ifdef HAVE_MODBUS_RTU_FLOW_CONTROL
    return modbus_new_rtu(request->serial_device,
                          request->serial_baud,
                          request->serial_parity,
                          request->serial_data_bits,
                          request->serial_stop_bits,
                          0);
#else
    return modbus_new_rtu(request->serial_device,
                          request->serial_baud,
                          request->serial_parity,
                          request->serial_data_bits,
                          request->serial_stop_bits);
#endif
}

static int
request_modbus_read_registers(modbus_t *ctx,
                              int address,
                              int count,
                              uint16_t *data) {
#ifdef HAVE_MODBUS_UINT16_REGISTER_BUFFERS
    return modbus_read_registers(ctx, address, count, data);
#else
    return modbus_read_registers(ctx, address, count, (uint8_t *)data);
#endif
}

static int
request_modbus_read_input_registers(modbus_t *ctx,
                                    int address,
                                    int count,
                                    uint16_t *data) {
#ifdef HAVE_MODBUS_UINT16_REGISTER_BUFFERS
    return modbus_read_input_registers(ctx, address, count, data);
#else
    return modbus_read_input_registers(ctx, address, count, (uint8_t *)data);
#endif
}

static int
request_modbus_write_bits(modbus_t *ctx,
                          int address,
                          int count,
                          const uint8_t *data) {
#ifdef HAVE_MODBUS_UINT8_BIT_BUFFERS
    return modbus_write_bits(ctx, address, count, data);
#else
    return modbus_write_bits(ctx, address, count, (const uint16_t *)data);
#endif
}

static void
request_init_serial_transport_locks(void) {
    for (size_t i = 0; i < SERIAL_TRANSPORT_LOCKS; i++) {
        pthread_mutex_init(&serial_transport_locks[i], NULL);
    }
}

static size_t
request_serial_transport_lock_index(const request_t *request) {
    unsigned long hash = 5381;
    const unsigned char *text = (const unsigned char *)request->serial_device;

    while (*text != '\0') {
        hash = ((hash << 5) + hash) + *text++;
    }
    return hash % SERIAL_TRANSPORT_LOCKS;
}

void
request_transport_lock(const request_t *request) {
    if (request == NULL || request->format != 1) {
        return;
    }
    pthread_once(&serial_transport_locks_once,
                 request_init_serial_transport_locks);
    pthread_mutex_lock(
        &serial_transport_locks[request_serial_transport_lock_index(request)]);
}

void
request_transport_unlock(const request_t *request) {
    if (request == NULL || request->format != 1) {
        return;
    }
    pthread_mutex_unlock(
        &serial_transport_locks[request_serial_transport_lock_index(request)]);
}

int
request_thread_reserve(void) {
    int reserved = 0;

    pthread_mutex_lock(&request_count_mutex);
    if (request_count < request_limit) {
        request_count++;
        reserved = 1;
    }
    pthread_mutex_unlock(&request_count_mutex);

    return reserved;
}

void
request_set_inflight_limit(unsigned int limit) {
    if (limit == 0) {
        return;
    }

    pthread_mutex_lock(&request_count_mutex);
    request_limit = limit;
    pthread_mutex_unlock(&request_count_mutex);
}

int
request_validate_modbus(const request_t *request, int one_based_address) {
    if (request == NULL || request->timeout == 0 || request->timeout > 999 ||
        request->slave_id == 0 || request->slave_id > 247 ||
        (one_based_address && request->register_addr == 0) ||
        request->register_addr > (one_based_address ? 65536U : 65535U)) {
        return -1;
    }

    if (request->function != 1 && request->function != 2 &&
        request->function != 3 && request->function != 4 &&
        request->function != 5 && request->function != 6 &&
        request->function != 15 && request->function != 16) {
        return -1;
    }

    if (request->function >= 1 && request->function <= 4) {
        if (request->register_count == 0 || request->register_count > 125) {
            return -1;
        }
    } else if (request->function == 15 || request->function == 16) {
        if (request->register_count == 0 || request->register_count > 123) {
            return -1;
        }
    } else if (request->function == 5 && request->register_count > 1) {
        return -1;
    }

    if (request->function <= 4 || request->function == 15 ||
        request->function == 16) {
        uint32_t last_address =
            request->register_addr + request->register_count - 1;
        if (last_address > (one_based_address ? 65536U : 65535U)) {
            return -1;
        }
    }

    return 0;
}

void
request_thread_release(void) {
    pthread_mutex_lock(&request_count_mutex);
    if (request_count > 0) {
        request_count--;
    }
    if (request_count == 0) {
        pthread_cond_broadcast(&request_count_cond);
    }
    pthread_mutex_unlock(&request_count_mutex);
}

int
request_wait_for_completion(unsigned int timeout_ms) {
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&request_count_mutex);
    while (request_count > 0) {
        int result = pthread_cond_timedwait(
            &request_count_cond, &request_count_mutex, &deadline);
        if (result == ETIMEDOUT) {
            pthread_mutex_unlock(&request_count_mutex);
            return -1;
        }
    }
    pthread_mutex_unlock(&request_count_mutex);
    return 0;
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
            free(joined);
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
    int transport_locked = 0;
    char failure_reason[128] = "request failed";

    pthread_detach(pthread_self());

    if (req->format == 1) {
        ctx = request_modbus_new_rtu(req);
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
    request_transport_lock(req);
    transport_locked = req->format == 1;
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
        result = request_modbus_read_registers(
            ctx, req->register_addr, req->register_count, req->data);
        break;
    case 4:
        result = request_modbus_read_input_registers(
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
        result = request_modbus_write_bits(
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
    if (transport_locked) {
        request_transport_unlock(req);
    }

    free(req);

    request_thread_release();

    pthread_exit(NULL);
}
