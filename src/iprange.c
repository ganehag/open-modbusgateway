/*
 * This file is part of Open Modbus Gateway (omg) https://github.com/ganehag/open-modbusgateway.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "iprange.h"

/** 
 * Function to check if an IP (string) is within the IP range declared by struct in6_addr ip and struct in6_addr netmask.
*/

// Check if char *ip is inside the range of ipaddr and netmask
// return 0 on success, -1 on failure
int
ip_in_range(const char *ip, const iprange_t *iprange) {
    struct in6_addr ipaddr;
    if (inet_pton(AF_INET6, ip, &ipaddr) != 1) {
        return -1;
    }

    // check if ipaddr is in range of iprange->ipaddr and iprange->netmask
    for (int i = 0; i < 16; i++) {
        char ipaddr_byte = ipaddr.s6_addr[i];
        char iprange_ipaddr_byte = iprange->ipaddr.s6_addr[i];
        char iprange_netmask_byte = iprange->netmask.s6_addr[i];

        // if ipaddr_byte is outside the range of iprange_ipaddr_byte and iprange_netmask_byte, return -1
        if ((ipaddr_byte & iprange_netmask_byte) != (iprange_ipaddr_byte & iprange_netmask_byte)) {
            return -1;
        }
    }

    return 0;
}



int
ip_cidr_to_in6(const char *ip_cidr, iprange_t *range) {
    // ensure ip_cidr is not NULL
    if (ip_cidr == NULL) {
        return IP_CIDR_INVALID_INPUT;
    }

    // ensure range is not NULL
    if (range == NULL) {
        return IP_CIDR_INVALID_INPUT;
    }

    char *ip = strdup(ip_cidr);
    char *slash = strchr(ip, '/');  // find the slash in the string
    if (slash == NULL) {
        return IP_CIDR_INVALID_INPUT;
    }
    *slash = '\0';
    slash++;

    // parse ip and store in range->ipaddr
    if (inet_pton(AF_INET6, ip, &(range->ipaddr)) != 1) {
        return IP_CIDR_INVALID_IP;
    }

    // parse CIDR mask, convert to netmask and store in range->netmask
    int netmask = atoi(slash);

    // check for errors in case atoi failed since atoi return 0 on error
    if (netmask == 0 && strncmp(slash, "0", 1) != 0) {
        return IP_CIDR_INVALID_CIDR;
    }

    // ensure netmask is valid
    if (netmask < 0 || netmask > 128) {
        return IP_CIDR_INVALID_CIDR;
    }

    // create netmask using cidr_to_netmask function
    if(cidr_to_netmask(netmask, &(range->netmask)) != 0) {
        return IP_CIDR_INVALID_CIDR;
    }

    return IP_CIDR_OK;
}

/**
 * CIDR to struct in6_addr netmask
 */
int
cidr_to_netmask(const int cidr, struct in6_addr *netmask) {
    // ensure cidr is not invalid
    if (cidr < 0 || cidr > 128) {
        return -1;
    }

    // set all bits in netmask to 0
    memset(netmask, 0, sizeof(struct in6_addr));

    // get the number of full 0xFF chunks from cidr
    int full_chunks = cidr / 8;

    // fill the full chunks with 0xFF
    for (int i = 0; i < full_chunks; i++) {
        netmask->s6_addr[i] = 0xFF;
    }

    // get the number of bits in the last chunk
    int last_chunk_bits = cidr % 8;

    // fill the last chunk with the remaining bits
    for (int i = 0; i < last_chunk_bits; i++) {
        netmask->s6_addr[full_chunks] |= (0x80 >> i);  // set the bit to 1, starting from the MSB
    }

    return 0;
}

int
in6_addr_to_string(const struct in6_addr *addr, char *str) {
    // ensure addr is not NULL
    if (addr == NULL) {
        return -1;
    }

    // ensure str is not NULL
    if (str == NULL) {
        return -1;
    }

    // convert in6_addr to string
    if (inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN) == NULL) {
        return -1;
    }

    return 0;
}

char *
ip_cidr_strerror(const int error_code) {
    switch(error_code) {
    case IP_CIDR_OK:
        return "IP_CIDR_OK";
    case IP_CIDR_INVALID_INPUT:
        return "IP_CIDR_INVALID_INPUT";
    case IP_CIDR_INVALID_IP:
        return "IP_CIDR_INVALID_IP";
    case IP_CIDR_INVALID_CIDR:
        return "IP_CIDR_INVALID_CIDR";
    default:
        return "IP_CIDR_UNKNOWN_ERROR";
    }

    return NULL;
}

uint8_t
in6_to_cidr_netmask(const struct in6_addr *netmask) {
    uint8_t cidr = 0;

    // loop through all bytes in netmask
    for (int i = 0; i < 16; i++) {
        uint8_t byte = netmask->s6_addr[i];

        // loop through all bits in byte
        for (int j = 0; j < 8; j++) {
            // if the bit is 1, increment cidr
            if (byte & (0x80 >> j)) {
                cidr++;
            }
        }
    }

    return cidr;
}
