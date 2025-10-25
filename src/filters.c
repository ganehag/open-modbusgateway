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

static int filter_match_tcp(filter_t *filter, request_t *request);
static int filter_match_serial(filter_t *filter, request_t *request);

int
filter_match(filter_t *filters, request_t *request) {
    filter_t *current = filters;

    if (current == NULL) {
        // No filters configured; allow request
        return 0;
    }

    int has_applicable = 0;

    while (current != NULL) {
        if (request->format == 0) {
            if (!current->applies_tcp) {
                current = current->next;
                continue;
            }
            has_applicable = 1;
            if (filter_match_one(current, request) == 0) {
                return 0;
            }
        } else if (request->format == 1) {
            if (!current->applies_serial) {
                current = current->next;
                continue;
            }
            has_applicable = 1;
            if (filter_match_serial(current, request) == 0) {
                return 0;
            }
        } else {
            return -1;
        }
        current = current->next;
    }

    return has_applicable ? -1 : 0;
}

// function to check if a message matches the content of request_t
// return 0 on success, -1 on failure
int
filter_match_one(filter_t *filter, request_t *request) {
    return filter_match_tcp(filter, request);
}

static int
filter_match_tcp(filter_t *filter, request_t *request) {
    char ip[INET6_ADDRSTRLEN];
    memset(ip, 0, sizeof(ip));

    if (filter->has_ip_range) {
        if (request->ip_type == IP_TYPE_IPV4) {
            snprintf(ip, sizeof(ip), "::ffff:%s", request->ip);
        } else if (request->ip_type == IP_TYPE_IPV6) {
            strncpy(ip, request->ip, sizeof(ip));
            ip[sizeof(ip) - 1] = '\0';
        } else if (request->ip_type == IP_TYPE_HOSTNAME) {
            return -1;
        } else {
            return -1;
        }

        if (ip_in_range(ip, &filter->iprange) != 0) {
            return -1;
        }
    }

    if (filter->has_port_range) {
        uint16_t port = (uint16_t)atoi(request->port);
        if (port < filter->port_min || port > filter->port_max) {
            return -1;
        }
    }

    if (filter->slave_id != request->slave_id) {
        return -1;
    }

    if (filter->function_code != request->function) {
        return -1;
    }

    if (request->register_addr < filter->register_address_min ||
        request->register_addr > filter->register_address_max) {
        return -1;
    }

    return 0;
}

static int
filter_match_serial(filter_t *filter, request_t *request) {
    if (filter->serial_id[0] != '\0' &&
        strcmp(filter->serial_id, "*") != 0 &&
        strncmp(filter->serial_id,
                request->serial_id,
                sizeof(filter->serial_id)) != 0) {
        return -1;
    }

    if (filter->slave_id != request->slave_id) {
        return -1;
    }

    if (filter->function_code != request->function) {
        return -1;
    }

    if (request->register_addr < filter->register_address_min ||
        request->register_addr > filter->register_address_max) {
        return -1;
    }

    return 0;
}

void
filter_print(filter_t *filter) {
    char ipaddr[INET6_ADDRSTRLEN];
    memset(ipaddr, 0, sizeof(ipaddr));

    char netmask[INET6_ADDRSTRLEN];
    memset(netmask, 0, sizeof(netmask));

    if (filter->has_ip_range) {
        inet_ntop(AF_INET6, &filter->iprange.ipaddr, ipaddr, sizeof(ipaddr));
        inet_ntop(
            AF_INET6, &filter->iprange.netmask, netmask, sizeof(netmask));
    }

    printf("Filter: ");
    if (filter->applies_tcp && filter->has_ip_range) {
        printf("%s/%s:%d-%d ",
               ipaddr,
               netmask,
               filter->port_min,
               filter->port_max);
    }
    if (filter->applies_serial) {
        printf("serial_id: %s ",
               filter->serial_id[0] != '\0' ? filter->serial_id : "(any)");
    }
    printf("slave_id: %d, function_code: %d, register_address: %d-%d, "
           "is_last: %d\n",
           filter->slave_id,
           filter->function_code,
           filter->register_address_min,
           filter->register_address_max,
           filter->next == NULL);
}
