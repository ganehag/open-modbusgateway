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
void test_filter_match_without_filters(void);
void test_filter_match_rejects_range_overrun(void);
void test_filter_match_serial(void);
void test_multiple_filters_match(void);
void test_clear_filters(void);

void test_config_parse_single_rule(void);
void test_config_parse_serial_gateway(void);
void test_config_parse_serial_rule(void);
void test_config_parse_automation(void);

void test_config_parse_file(void);
void test_parse_option_range_ok(void);
void test_config_file_parser_errors(void);
void test_parse_option_range_errors(void);
void test_validate_config_without_rules(void);
void test_validate_config_tls_options(void);
void test_config_rejects_legacy_tls(void);
void test_config_parses_request_limit(void);
void test_config_rejects_unknown_or_malformed_options(void);
void test_config_parser_malformed_input_smoke(void);

void test_trim_functions(void);

void test_mqtt_format1_slave_override(void);
void test_mqtt_format1_no_override(void);
void test_mqtt_format1_reject_extra_token(void);
void test_mqtt_format1_missing_write_payload(void);
void test_mqtt_format1_serial_filter_blocks(void);
void test_mqtt_format1_serial_filter_allows(void);
void test_mqtt_rejects_invalid_write_values(void);
void test_mqtt_accepts_non_terminated_payload(void);
void test_mqtt_rejects_invalid_tcp_address(void);
void test_mqtt_rejects_malformed_numeric_fields(void);
void test_mqtt_parser_malformed_input_smoke(void);

void test_automation_callbacks(void);
void test_automation_instruction_limit(void);
void test_automation_memory_limit(void);
void test_automation_request_hooks(void);

#endif
