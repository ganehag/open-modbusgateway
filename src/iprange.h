#ifndef IPRANGE_H
#define IPRANGE_H

#include <netinet/in.h>

typedef struct in6_addr ip6addr_t;

typedef struct {
	struct in6_addr ipaddr;
	struct in6_addr netmask;
} iprange_t;

// error codes for ip_cidr_to_in6
#define IP_CIDR_OK 0
#define IP_CIDR_INVALID_INPUT -1
#define IP_CIDR_INVALID_IP -2
#define IP_CIDR_INVALID_CIDR -3
#define IP_CIDR_INVALID_NETMASK -4

int ip_in_range(const char *ip, const iprange_t *range);
int ip_cidr_to_in6(const char *ip_cidr, iprange_t *range);
int cidr_to_netmask(const int cidr, struct in6_addr *netmask);
char *
ip_cidr_strerror(const int error_code);
int
in6_addr_to_string(const struct in6_addr *addr, char *str);

uint8_t
in6_to_cidr_netmask(const struct in6_addr *addr);

#endif // IPRANGE_H
