#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../src/iprange.h"
#include "../src/filters.h"

void
test_filter_add(void) {
	// allocate the first filter
	filter_t *filters_head = NULL;
	filter_t *current = filters_head;
	
	// loop through the filters and add them to the list
	for (int i = 0; i < 20; i++) {
		// allocate the new filter
		filter_t *new_filter = malloc(sizeof(filter_t));
		new_filter->next = NULL;

		// assign values to the filter
		CU_ASSERT_EQUAL(ip_cidr_to_in6("::ffff:192.168.1.1/120", &new_filter->iprange), 0);

		new_filter->port_min = 502;
		new_filter->port_max = 502;
		new_filter->slave_id = 1;
		new_filter->function_code = 3;  // read holding registers
		new_filter->register_address_min = 0;
		new_filter->register_address_max = 1000;

		filter_add(&filters_head, new_filter);
	}

	// check that the filters are added to the list
	current = filters_head;
	for (int i = 0; i < 20; i++) {
		CU_ASSERT_PTR_NOT_NULL(current);
		current = current->next;
	}

	// cleanup
	filter_free(&filters_head);

	CU_ASSERT_PTR_NULL(filters_head);
}

void
test_filter_match(void) {
	filter_t *filter = malloc(sizeof(filter_t));
	memset(filter, 0, sizeof(filter_t));

	CU_ASSERT_EQUAL(ip_cidr_to_in6("::ffff:192.168.1.1/120", &filter->iprange), 0);

	filter->port_min = 502;
	filter->port_max = 505;
	filter->slave_id = 1;
	filter->function_code = 3; // Read Holding Registers
	filter->register_address_min = 0;
	filter->register_address_max = 10;

	filter_add(&filter, filter);

	request_t request = {
		.ip_type = IP_TYPE_IPV6,
		.ip = "::ffff:192.168.1.102",
		.port = "502",
		.slave_id = 1,
		.function = 3,
		.register_addr = 0,
		.register_count = 1
	};

	// loop through all modbus addresses and check if they match the filter
	for (uint16_t i = 0; i <= 10; i++) {
		request.register_addr = i;
		CU_ASSERT_EQUAL(filter_match(filter, &request), 0);
	}

	// now test outside the range
	for (uint16_t i = 11; i <= 20; i++) {
		request.register_addr = i;
		CU_ASSERT_EQUAL(filter_match(filter, &request), -1);
	}

	// reset register address to inside the range
	request.register_addr = 0; 

	// test wrong slave id
	request.slave_id = 2;

	for (uint16_t i = 0; i <= 10; i++) {
		request.register_addr = i;
		CU_ASSERT_EQUAL(filter_match(filter, &request), -1);
	}

	// reset slave id
	request.slave_id = 1;

	// test wrong function code
	request.function = 4;

	for (uint16_t i = 0; i <= 10; i++) {
		request.register_addr = i;
		CU_ASSERT_EQUAL(filter_match(filter, &request), -1);
	}

	// reset function code
	request.function = 3;

	// test wrong port
	memset(request.port, 0, sizeof(request.port));
	strcpy(request.port, "5020");

	for (uint16_t i = 0; i <= 10; i++) {
		request.register_addr = i;
		CU_ASSERT_EQUAL(filter_match(filter, &request), -1);
	}

	// cleanup
	free(filter);
}

void
test_filter_match_without_filters(void) {
	request_t request;
	memset(&request, 0, sizeof(request));

	request.format = 0;
	request.ip_type = IP_TYPE_IPV4;
	strncpy(request.ip, "192.168.1.10", sizeof(request.ip) - 1);
	strncpy(request.port, "502", sizeof(request.port) - 1);
	request.slave_id = 1;
	request.function = 3;
	request.register_addr = 1;
	request.register_count = 1;

	CU_ASSERT_EQUAL(filter_match(NULL, &request), 0);
}

void
test_multiple_filters_match(void) {
	filter_t *filters_head = NULL;
	filter_t *current = filters_head;

	// allocate the new filter
	filter_t *filter1 = malloc(sizeof(filter_t));
	filter1->next = NULL;

	// assign values to the filter
	CU_ASSERT_EQUAL(ip_cidr_to_in6("::ffff:192.168.1.1/128", &filter1->iprange), 0);

	filter1->port_min = 502;
	filter1->port_max = 502;
	filter1->slave_id = 1;
	filter1->function_code = 3;  // read holding registers
	filter1->register_address_min = 0;
	filter1->register_address_max = 10;

	filter_add(&filters_head, filter1);

	// allocate the new filter
	filter_t *filter2 = malloc(sizeof(filter_t));
	filter2->next = NULL;

	// assign values to the filter
	CU_ASSERT_EQUAL(ip_cidr_to_in6("::ffff:192.168.1.2/128", &filter2->iprange), 0);

	filter2->port_min = 502;
	filter2->port_max = 502;
	filter2->slave_id = 1;
	filter2->function_code = 3;  // read holding registers
	filter2->register_address_min = 0;
	filter2->register_address_max = 10;

	filter_add(&filters_head, filter2);

	// allocate the new filter
	filter_t *filter3 = malloc(sizeof(filter_t));
	filter3->next = NULL;

	// assign values to the filter
	CU_ASSERT_EQUAL(ip_cidr_to_in6("::ffff:192.168.1.100/128", &filter3->iprange), 0);

	filter3->port_min = 502;
	filter3->port_max = 502;
	filter3->slave_id = 1;
	filter3->function_code = 3;  // read holding registers
	filter3->register_address_min = 0;
	filter3->register_address_max = 10;

	filter_add(&filters_head, filter3);

	// check that the filters are added to the list
	current = filters_head;

	CU_ASSERT_PTR_NOT_NULL(current); // filter1
	current = current->next;

	CU_ASSERT_PTR_NOT_NULL(current); // filter2
	current = current->next;

	CU_ASSERT_PTR_NOT_NULL(current); // filter3
	current = current->next;

	CU_ASSERT_PTR_NULL(current);  // end of list

	// check that the filters match a couple of requests

	// request 1
	request_t request1 = {
		.ip_type = IP_TYPE_IPV4,
		.ip = "192.168.1.1",
		.port = "502",
		.slave_id = 1,
		.function = 3,
		.register_addr = 0,
		.register_count = 1
	};

	// request 2
	request_t request2 = {
		.ip_type = IP_TYPE_IPV4,
		.ip = "192.168.1.2",
		.port = "502",
		.slave_id = 1,
		.function = 3,
		.register_addr = 0,
		.register_count = 1
	};

	// request 3
	request_t request3 = {
		.ip_type = IP_TYPE_IPV4,
		.ip = "192.168.1.100",
		.port = "502",
		.slave_id = 1,
		.function = 3,
		.register_addr = 0,
		.register_count = 1
	};

	// check that the requests match the filters
	CU_ASSERT_EQUAL(filter_match(filters_head, &request1), 0);
	CU_ASSERT_EQUAL(filter_match(filters_head, &request2), 0);
	CU_ASSERT_EQUAL(filter_match(filters_head, &request3), 0);

	// cleanup
	filter_free(&filters_head);
}
