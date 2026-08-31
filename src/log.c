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
    if (logfile != NULL && logfile != stderr) {
        fclose(logfile);
    }

    logfile = fopen(path, "a");
    if (logfile == NULL) {
        fprintf(stderr, "Failed to open logfile: %s\n", path);
        logfile = stderr;
        return;
    }

    setbuf(logfile, NULL); // disable buffering
}

void
close_logfile(void) {
    if (logfile != NULL && logfile != stderr) {
        fclose(logfile);
    }
    logfile = stderr;
}

void
flog(FILE *stream, const char *format, ...) {
    if (stream == NULL || format == NULL) {
        return;
    }
    va_list args;

    // prefix the output with timestamp
    time_t now = time(NULL);
    struct tm timestamp = {0};
    localtime_r(&now, &timestamp);

    // time in rf3339 format
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", &timestamp);

    va_start(args, format);
    flockfile(stream);
    fprintf(stream, "[%s] ", timebuf);
    vfprintf(stream, format, args);
    funlockfile(stream);
    va_end(args);
}

void
flog_filter(FILE *stream, filter_t *head) {
    if (stream == NULL) {
        return;
    }
    flockfile(stream);
    filter_t *current = head;
    while (current != NULL) {
        // prefix the output with timestamp
        time_t now = time(NULL);
        struct tm timestamp = {0};
        localtime_r(&now, &timestamp);

        // time in rf3339 format
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%FT%T%z", &timestamp);

        // convert iprange.ipaddr to string
        char ipaddr[INET6_ADDRSTRLEN];
        memset(ipaddr, 0, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &current->iprange.ipaddr, ipaddr, INET6_ADDRSTRLEN);

        fprintf(stream, "[%s] allow rule {", timebuf);
        if (current->applies_tcp && current->has_hostname) {
            fprintf(stream, "%s", current->hostname);
        } else if (current->applies_tcp && current->has_ip_range) {
            fprintf(stream,
                    "%s/%d",
                    ipaddr,
                    in6_to_cidr_netmask(&current->iprange.netmask));
        } else if (current->applies_serial) {
            fprintf(stream, "serial:%s", current->serial_id);
        }
        if (current->has_port_range) {
            fprintf(stream, ":%d-%d", current->port_min, current->port_max);
        }
        fprintf(stream,
                ", slave_id: %d, function_code: %d, register_address: %u-%u}"
                "\n",
                current->slave_id,
                current->function_code,
                current->register_address_min,
                current->register_address_max);

        current = current->next;
    }
    funlockfile(stream);
}
