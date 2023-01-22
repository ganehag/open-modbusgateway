#include <arpa/inet.h>

#include "test.h"
#include "../src/iprange.h"

void
test_ip_in_range(void) {
	const char *ip = "::ffff:192.168.1.102";
	iprange_t iprange;

 	if(ip_cidr_to_in6("::ffff:192.168.1.1/120", &iprange) != 0) {
 		CU_FAIL("ip_cidr_to_in6 failed");
 	}

	CU_ASSERT_TRUE(ip_in_range(ip, &iprange) == 0);
}

void
test_ip_not_in_range(void) {
	const char *ip2 = "::ffff:192.168.1.102";
	const char *ip_filter2 = "::ffff:192.168.1.1/128";
	iprange_t iprange2;

	if(ip_cidr_to_in6(ip_filter2, &iprange2) != 0) {
 		CU_FAIL("ip_cidr_to_in6 failed");
 	}

	CU_ASSERT_FALSE(ip_in_range(ip2, &iprange2) == 0);
}
	

void
test_ip_cidr_to_in6(void) {
	const char *ip_cidr = "::ffff:192.168.1.1/120";
	iprange_t iprange;

	CU_ASSERT_TRUE(ip_cidr_to_in6(ip_cidr, &iprange) == 0);

	// ipv6 netmask of /120 as a char array
	uint8_t expected_netmask[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};
	const uint8_t *actual_netmask = iprange.netmask.s6_addr;

	CU_ASSERT_TRUE(memcmp(expected_netmask, actual_netmask, 16) == 0);

	// ::ffff:c0a8:101 as a char array
	uint8_t expected_ipaddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01};
	CU_ASSERT_TRUE(memcmp(expected_ipaddr, iprange.ipaddr.s6_addr, 16) == 0);

	// test of invalid ip_cidr
	CU_ASSERT_TRUE(ip_cidr_to_in6("", &iprange) != 0);

	// test of invalid ip_cidr
	CU_ASSERT_TRUE(ip_cidr_to_in6(NULL, &iprange) != 0);

	// test of invalid ip_cidr
	CU_ASSERT_TRUE(ip_cidr_to_in6("::ffff:notanip/120", &iprange) != 0);

	// test of invalid ip_cidr withouth netmask
	CU_ASSERT_TRUE(ip_cidr_to_in6("::ffff:192.168.1.1", &iprange) != 0);

	// test of invalid ip_cidr with invalid netmask
	CU_ASSERT_TRUE(ip_cidr_to_in6("::ffff:192.168.1.1/129", &iprange) != 0);

	// test of invalid ip_cidr with invalid netmask
	CU_ASSERT_TRUE(ip_cidr_to_in6("::ffff:192.168.1.1/-1", &iprange) != 0);

	// test of invalid ip_cidr with invalid netmask
	CU_ASSERT_TRUE(ip_cidr_to_in6("::ffff:192.168.1.1/abc", &iprange) != 0);
}

void 
test_cidr_to_netmask(void) {
	// -- 120 bit netmask

	// Convert a CIDR notation to a netmask
	struct in6_addr netmask;
	CU_ASSERT_TRUE(cidr_to_netmask(120, &netmask) == 0);

	// ipv6 netmask of /120 as a char array
	const uint8_t expected_netmask[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};
	CU_ASSERT_TRUE(memcmp(netmask.s6_addr, expected_netmask, 16) == 0);

	// -- 64 bit netmask

	// Convert a CIDR notation to a netmask
	struct in6_addr netmask2;
	CU_ASSERT_TRUE(cidr_to_netmask(64, &netmask2) == 0);

	const uint8_t expected_netmask2[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	CU_ASSERT_TRUE(memcmp(netmask2.s6_addr, expected_netmask2, 16) == 0);

	// -- 0 bit netmask

	// Convert a CIDR notation to a netmask
	struct in6_addr netmask3;
	CU_ASSERT_TRUE(cidr_to_netmask(0, &netmask3) == 0);

	const uint8_t expected_netmask3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	CU_ASSERT_TRUE(memcmp(netmask3.s6_addr, expected_netmask3, 16) == 0);

	// -- 128 bit netmask

	// Convert a CIDR notation to a netmask
	struct in6_addr netmask4;
	CU_ASSERT_TRUE(cidr_to_netmask(128, &netmask4) == 0);

	const uint8_t expected_netmask4[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	CU_ASSERT_TRUE(memcmp(netmask4.s6_addr, expected_netmask4, 16) == 0);
}