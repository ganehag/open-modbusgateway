#include <stdlib.h>

#include "test.h"
#include "../src/config_parser.h"
#include "../src/filters.h"

// struct to handle expected port and register values
typedef struct {
	range_u32_t port;
	range_u32_t register_addr;
} expected_port_reg_t;

const char file_content[] = "config rule\n"
    "    option ip '::ffff:192.168.1.1/120'\n"
    "    option port '502, 5020-5025'\n"
    "    option slave_id '1'\n"
    "    option function '3'\n"
    "    option register_address '0-100'\n\n"
    "config rule\n"
    "    option ip '::ffff:192.168.2.1/120'\n"
    "    option port '502, 5020-5025'\n"
    "    option slave_id '1'\n"
    "    option function '3'\n"
    "    option register_address '0-100'\n\n"
    "config rule\n"
    "    option ip '::ffff:172.16.0.1/120'\n"
    "    option port '5020'\n"
    "    option slave_id '1'\n"
    "    option function '3'\n"
    "    option register_address '100-200'\n";

// file with single working rule
const char file_content_single[] = "config rule\n"
	"    option ip '::ffff:192.168.100.1/120'\n"
	"\t\t\r\voption port '502, 5020-5025'\n"
	"    option slave_id '1'\n"
	"    option function '4'\n"
	"    option register_address '0-100,    50-200'\n";

// config file content with too many port, ranges > 8
const char file_content_too_many_port_ranges[] = "config rule\n"
	"    option ip '::ffff:192.168.1.1/120'\n"
	"    option port '502, 5020-5025, 5026-5030, 5031-5035, 5036-5040, 5041-5045, 5046-5050, 5051-5055, 5056-5060'\n"
	"    option slave_id '1'\n"
	"    option function '3'\n"
	"    option register_address '0-100'\n\n";

void
callback_function_helper(void *data, rule_t *rule) {
	if (data == NULL) {
		return;
	}

	// data is a pointer to a filter_t struct
	filter_t **head = (filter_t **) data;

	// loop over all the port ranges until we find a rule that is not initialized
	for (int i = 0; i < MAX_RANGES; i++) {
		if (rule->port[i].initialized == 0) {
			break;
		}
	}

	// the same, but for register_address
	for (int i = 0; i < MAX_RANGES; i++) {
		if (rule->register_addr[i].initialized == 0) {
			break;
		}
	}

	// add the rule to the filter, so we can check it later
	// since each rule contains multiple port ranges, and multiple register address ranges, we need to add the rule multiple times

	// loop over all the port ranges until we find a rule that is not initialized
	for (int i = 0; i < MAX_RANGES; i++) {
		if (rule->port[i].initialized == 0) {
			break;
		}
		// loop over all the register address ranges until we find a rule that is not initialized
		for (int j = 0; j < MAX_RANGES; j++) {
			if (rule->register_addr[j].initialized == 0) {
				break;
			}

			filter_t *new_filter = calloc(1, sizeof(filter_t));
			if(ip_cidr_to_in6(rule->ip, &new_filter->iprange ) != 0) {
				return; // unable to parse ip
			}

			new_filter->slave_id = rule->slave_id;
			new_filter->function_code = rule->function;
			new_filter->port_min = rule->port[i].min;
			new_filter->port_max = rule->port[i].max;
			new_filter->register_address_min = rule->register_addr[j].min;
			new_filter->register_address_max = rule->register_addr[j].max;

			// add the rule to the filter
			filter_add(head, new_filter);
		}
	}
}


void
test_config_parse_file(void) {
	// create a temporary file
	FILE *file = tmpfile();
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);

	// write some lines to the file
	fprintf(file, "%s", file_content);

	// rewind the file
	rewind(file);

	// parse the file
	// int config_parse_file(FILE *file, void (*callback)(void *data, rule_t *rule), void *user_obj);
	CU_ASSERT_EQUAL(config_parse_file(file, &callback_function_helper, NULL), 0);

	// remove the file
	fclose(file);  // not needed, but good practice
}

void
test_config_parse_single_rule(void) {
	// create a temporary file
	FILE *file = tmpfile();
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);

	// filter head to store the rules
	filter_t *head = NULL;

	// write some lines to the file
	fprintf(file, "%s", file_content_single);

	// rewind the file
	rewind(file);

	// parse the file
	// int config_parse_file(FILE *file, void (*callback)(void *data, rule_t *rule), void *user_obj);
	CU_ASSERT_EQUAL(config_parse_file(file, &callback_function_helper, &head), 0);

	// check the config
	CU_ASSERT_PTR_NOT_NULL(head);


	iprange_t expected_cidr = {
		// ::ffff:192.168.100.1
		.ipaddr = { .s6_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x64, 0x01} },
		.netmask = { .s6_addr = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 } }
	};

	// expected port and register address results
	expected_port_reg_t exp_port_reg[] = {
		{
			{1, 502, 502},
			{1, 0, 100},
		},
		{
			{1, 502, 502},
			{1, 50, 200},
		},
		{
			{1, 5020, 5025},
			{1, 0, 100},
		},
		{
			{1, 5020, 5025},
			{1, 50, 200},
		}
	};

	// loop all the rules
	filter_t *current = head;
	int i = 0;
	while (current != NULL) {
		// check the ip
		// debug print the ip
		char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &current->iprange.netmask, ip, sizeof(ip));

		CU_ASSERT_STRING_EQUAL(current->iprange.ipaddr.s6_addr, expected_cidr.ipaddr.s6_addr);
		CU_ASSERT_STRING_EQUAL(current->iprange.netmask.s6_addr, expected_cidr.netmask.s6_addr);

		// check slave id
		CU_ASSERT_EQUAL(current->slave_id, 1);

		// check function code
		CU_ASSERT_EQUAL(current->function_code, 4);

		// compare current and expected
		CU_ASSERT_EQUAL(current->port_min, exp_port_reg[i].port.min);
		CU_ASSERT_EQUAL(current->port_max, exp_port_reg[i].port.max);
		CU_ASSERT_EQUAL(current->register_address_min, exp_port_reg[i].register_addr.min);
		CU_ASSERT_EQUAL(current->register_address_max, exp_port_reg[i].register_addr.max);

		current = current->next;
		i++;
	}

	// free the filter list
	filter_free(&head);

	// remove the file
	fclose(file);  // not needed, but good practice
}

void
test_config_file_parser_errors(void) {
	// create a temporary file
	FILE *file = tmpfile();
	CU_ASSERT_PTR_NOT_NULL_FATAL(file);

	// write some lines to the file
	fprintf(file, "%s", file_content_too_many_port_ranges);

	// rewind the file
	rewind(file);

	// parse the file
	int error;
	error = config_parse_file(file, NULL, NULL);

	CU_ASSERT_NOT_EQUAL(error, 0);

	// remove the file
	fclose(file);  // not needed, but good practice
}

void
test_parse_option_range_ok(void) {
	char *range_1 = "1-100";
	range_u32_t list[MAX_RANGES];
	memset(list, 0, sizeof(list));

	int error = 0;
	error = parse_option_range(range_1, list);
	CU_ASSERT_EQUAL(error, 0);

	CU_ASSERT_EQUAL(list[0].min, 1);
	CU_ASSERT_EQUAL(list[0].max, 100);

	char *range_8 = "0-100, 200-300, 400-500, 600-700, 800-900, 1000-1100, 1200-1300, 1400-1500";
	memset(list, 0, sizeof(list));
	error = parse_option_range(range_8, list);
	CU_ASSERT_EQUAL(error, 0);

	CU_ASSERT_EQUAL(list[0].min, 0);
	CU_ASSERT_EQUAL(list[0].max, 100);
	CU_ASSERT_EQUAL(list[1].min, 200);
	CU_ASSERT_EQUAL(list[1].max, 300);
	CU_ASSERT_EQUAL(list[2].min, 400);
	CU_ASSERT_EQUAL(list[2].max, 500);
	CU_ASSERT_EQUAL(list[3].min, 600);
	CU_ASSERT_EQUAL(list[3].max, 700);
	CU_ASSERT_EQUAL(list[4].min, 800);
	CU_ASSERT_EQUAL(list[4].max, 900);
	CU_ASSERT_EQUAL(list[5].min, 1000);
	CU_ASSERT_EQUAL(list[5].max, 1100);
	CU_ASSERT_EQUAL(list[6].min, 1200);
	CU_ASSERT_EQUAL(list[6].max, 1300);
	CU_ASSERT_EQUAL(list[7].min, 1400);
	CU_ASSERT_EQUAL(list[7].max, 1500);

	// test a range value larger than 32 bits
	char *range_32bit_overflow = "0-4294967296";
	memset(list, 0, sizeof(list));
	error = parse_option_range(range_32bit_overflow, list);
	CU_ASSERT_EQUAL(error, PARSE_RANGE_ERROR_OVERFLOW);
}

void
test_parse_option_range_errors(void) {
	// parse_option_range(char *option_value, range_u32_t *list)
	range_u32_t list[MAX_RANGES];

	char *options_too_many_ranges = "1, 2, 3, 4, 5, 6, 7, 8, 9"; // 502, 5020-5025, 5026-5030, 5031-5035, 5036-5040, 5041-5045, 5046-5050, 5051-5055, 5056-5060

	int error = 0;

	error = parse_option_range(options_too_many_ranges, list);

	// ensure we get an error of PARSE_RANGE_ERROR_MAX_RANGES
	CU_ASSERT_EQUAL(error, PARSE_RANGE_ERROR_MAX_RANGES);

	char *options_invalid_range = "1, 2, 3, 4, 5, 6, 7, 8-9"; 

}

void
test_trim_functions(void) {
	/*
	functions to test:
	char *trim_token(char *str, char trim_char, size_t len);
	char *trim_left(char *str, size_t len);
	char *trim(char *str, size_t len);
	*/

	// a couple of test strings, followed be a couple of expected results
	char str[] = "  hello world  ";
	char *expected = "hello world";

	char str2[] = "  hello world  ";
	char *expected2 = "hello world  ";

	char str4[] = "''hello world''";
	char *expected4 = "hello world";

	char str5[] = " \t\r\vhello world\t\r\v ";
	char *expected5 = "hello world";

	// run the tests, start by executing the trim function on all the test strings
	// the calls will modify the strings, so we need to copy the test strings first
	char str_copy[100];

	// test for str
	memset(str_copy, 0, sizeof(str_copy));
	strcpy(str_copy, str);
	char *result = trim(str_copy, strlen(str_copy));
	CU_ASSERT_STRING_EQUAL(result, expected);

	// test for str2
	memset(str_copy, 0, sizeof(str_copy));
	strcpy(str_copy, str2);
	result = trim_left(str_copy, strlen(str_copy));
	CU_ASSERT_STRING_EQUAL(result, expected2);

	// test for str4
	memset(str_copy, 0, sizeof(str_copy));
	strcpy(str_copy, str4);
	result = trim_token(str_copy, '\'', strlen(str_copy));
	CU_ASSERT_STRING_EQUAL(result, expected4);

	// test for str5
	memset(str_copy, 0, sizeof(str_copy));
	strcpy(str_copy, str5);
	result = trim(str_copy, strlen(str_copy));
	CU_ASSERT_STRING_EQUAL(result, expected5);
}