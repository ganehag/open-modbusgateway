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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filters.h"
#include "iprange.h"
#include "request.h"

filter_t *
filter_new(void) {
    // allocate memory for filter_t
    filter_t *filter = calloc(1, sizeof(filter_t));
    if (!filter) {
        return NULL;
    }

    // set defaults
    filter->next = NULL;

    return filter;
}

// add_filter function
void
filter_add(filter_t **head, filter_t *filter) {
    filter_t *current = *head;

    if (current == NULL) {
        *head = filter;
        return;
    }

    while (current->next != NULL) {
        current = current->next;
    }

    current->next = filter;

    // ensure next is NULL
    filter->next = NULL;
}

// clear filters function
void
filter_free(filter_t **head) {
    filter_t *current = *head;
    filter_t *next;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    *head = NULL;
}

int
filter_match(filter_t *filters, request_t *request) {
    filter_t *current = filters;

    while (current != NULL) {
        if (filter_match_one(current, request) == 0) {
            return 0;
        }
        current = current->next;
    }

    return -1;
}

// function to check if a message matches the content of request_t
// return 0 on success, -1 on failure
int
filter_match_one(filter_t *filter, request_t *request) {
    char ip[INET6_ADDRSTRLEN];
    memset(ip, 0, INET6_ADDRSTRLEN);

    // check if request is in IPv4 or IPv6 format
    if (request->ip_type == IP_TYPE_IPV4) {
        // convert IPv4 to IPv6
        snprintf(ip, INET6_ADDRSTRLEN, "::ffff:%s", request->ip);
    } else if (request->ip_type == IP_TYPE_IPV6) {
        strncpy(ip, request->ip, INET6_ADDRSTRLEN);
    } else if (request->ip_type == IP_TYPE_HOSTNAME) {
        // TODO: implement hostname lookup
        return -1;
    } else {
        // unknown ip_type
        return -1;
    }

    // check if ip is in range
    if (ip_in_range(ip, &filter->iprange) != 0) {
        return -1;
    }

    uint16_t port = atoi(request->port);
    // ensure port is within range
    if (port < filter->port_min || port > filter->port_max) {
        return -1;
    }

    if (filter->slave_id != request->slave_id) {
        return -1;
    }

    if (filter->function_code != request->function) {
        return -1;
    }

    // check if register is in range of min and max addresses
    if (request->register_addr < filter->register_address_min ||
        request->register_addr > filter->register_address_max) {
        return -1;
    }

    return 0;
}

void
filter_print(filter_t *filter) {
    // convert iprange.ipaddr to string
    char ipaddr[INET6_ADDRSTRLEN];
    memset(ipaddr, 0, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &filter->iprange.ipaddr, ipaddr, INET6_ADDRSTRLEN);

    // convert iprange.netmask to string
    char netmask[INET6_ADDRSTRLEN];
    memset(netmask, 0, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &filter->iprange.netmask, netmask, INET6_ADDRSTRLEN);

    // print the filter in a structured way
    printf("Filter: %s/%s:%d-%d, slave_id: %d, function_code: %d, "
           "register_address: %d-%d, is_last: %d\n",
           ipaddr,
           netmask,
           filter->port_min,
           filter->port_max,
           filter->slave_id,
           filter->function_code,
           filter->register_address_min,
           filter->register_address_max,
           filter->next == NULL);
}
