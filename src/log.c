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

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "filters.h"
#include "log.h"

FILE *logfile = NULL;

void
set_logfile(const char *path) {
    if (logfile != NULL) {
        fclose(logfile);
    }

    logfile = fopen(path, "a");
    if (logfile == NULL) {
        fprintf(stderr, "Failed to open logfile: %s\n", path);
    }

    setbuf(logfile, NULL); // disable buffering
}

void
flog(FILE *stream, const char *format, ...) {
    va_list args;

    // prefix the output with timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // time in rf3339 format
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", t);

    va_start(args, format);
    fprintf(stream, "[%s] ", timebuf);
    vfprintf(stream, format, args);
    va_end(args);
}

void
flog_filter(FILE *stream, filter_t *head) {
    filter_t *current = head;
    while (current != NULL) {
        // prefix the output with timestamp
        time_t now = time(NULL);
        struct tm *t = localtime(&now);

        // time in rf3339 format
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%FT%T%z", t);

        // convert iprange.ipaddr to string
        char ipaddr[INET6_ADDRSTRLEN];
        memset(ipaddr, 0, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &current->iprange.ipaddr, ipaddr, INET6_ADDRSTRLEN);

        fprintf(stream,
                "[%s] allow rule {%s/%d:%d-%d, slave_id: %d, function_code: "
                "%d, register_address: %d-%d}\n",
                timebuf,
                ipaddr,
                in6_to_cidr_netmask(&current->iprange.netmask),
                current->port_min,
                current->port_max,
                current->slave_id,
                current->function_code,
                current->register_address_min,
                current->register_address_max);

        current = current->next;
    }
}
