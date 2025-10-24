#ifndef TEST_H
#define TEST_H

#include <CUnit/Automated.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/Console.h>

void test_ip_in_range(void);
void test_ip_not_in_range(void);
void test_ip_cidr_to_in6(void);
void test_cidr_to_netmask(void);
void test_filter_add(void);

void test_filter_match(void);
void test_multiple_filters_match(void);
void test_clear_filters(void);

void test_config_parse_single_rule(void);
void test_config_parse_serial_gateway(void);

void test_config_parse_file(void);
void test_parse_option_range_ok(void);
void test_config_file_parser_errors(void);
void test_parse_option_range_errors(void);

void test_trim_functions(void);

#endif
