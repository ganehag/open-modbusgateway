#include "config.h"

#include "../src/log.h"
#include "test.h"

int
main(void) {
    // Initialize the CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry()) {
        return CU_get_error();
    }

    // disable display of errors from stderr
    CU_set_output_filename("cunit_test.log");

    // CU_set_error_action(CUEA_IGNORE);

    CU_pSuite suite1 = CU_add_suite("IP functions", NULL, NULL);

    CU_add_test(suite1, "test_ip_in_range", test_ip_in_range);
    CU_add_test(suite1, "test_ip_not_in_range", test_ip_not_in_range);
    CU_add_test(suite1, "test_ip_cidr_to_in6", test_ip_cidr_to_in6);
    CU_add_test(suite1, "test_cidr_to_netmask", test_cidr_to_netmask);

    CU_pSuite suite2 = CU_add_suite("Filter functions", NULL, NULL);
    CU_add_test(suite2, "test_filter_add", test_filter_add);
    CU_add_test(suite2, "test_filter_match", test_filter_match);
    CU_add_test(suite2,
                "test_filter_match_without_filters",
                test_filter_match_without_filters);
    CU_add_test(suite2,
                "test_filter_match_rejects_range_overrun",
                test_filter_match_rejects_range_overrun);
    CU_add_test(suite2, "test_filter_match_serial", test_filter_match_serial);
    CU_add_test(
        suite2, "test_multiple_filters_match", test_multiple_filters_match);

    CU_pSuite suite3 = CU_add_suite("Config functions", NULL, NULL);
    CU_add_test(suite3, "test_config_parse_file", test_config_parse_file);
    CU_add_test(
        suite3, "test_parse_option_range_ok", test_parse_option_range_ok);
    CU_add_test(suite3,
                "test_parse_option_range_errors",
                test_parse_option_range_errors);
    CU_add_test(suite3,
                "test_config_file_parser_errors",
                test_config_file_parser_errors);
    CU_add_test(
        suite3, "test_config_parse_single_rule", test_config_parse_single_rule);
    CU_add_test(suite3,
                "test_config_parse_serial_gateway",
                test_config_parse_serial_gateway);
    CU_add_test(
        suite3, "test_config_parse_serial_rule", test_config_parse_serial_rule);
    CU_add_test(
        suite3, "test_config_parse_automation", test_config_parse_automation);
    CU_add_test(suite3,
                "test_validate_config_without_rules",
                test_validate_config_without_rules);
    CU_add_test(suite3,
                "test_validate_config_tls_options",
                test_validate_config_tls_options);
    CU_add_test(suite3,
                "test_config_rejects_legacy_tls",
                test_config_rejects_legacy_tls);
    CU_add_test(suite3,
                "test_config_parses_request_limit",
                test_config_parses_request_limit);
    CU_add_test(suite3,
                "test_config_rejects_unknown_or_malformed_options",
                test_config_rejects_unknown_or_malformed_options);
    CU_add_test(suite3,
                "test_config_rejects_oversized_values_and_ranges",
                test_config_rejects_oversized_values_and_ranges);
    CU_add_test(suite3,
                "test_config_rejects_invalid_or_incomplete_rules",
                test_config_rejects_invalid_or_incomplete_rules);
    CU_add_test(suite3,
                "test_config_allows_adjacent_sections",
                test_config_allows_adjacent_sections);
    CU_add_test(suite3,
                "test_config_preserves_hashes_and_rejects_bad_quotes",
                test_config_preserves_hashes_and_rejects_bad_quotes);
    CU_add_test(suite3,
                "test_hostname_validation_and_storage",
                test_hostname_validation_and_storage);
    CU_add_test(suite3,
                "test_config_parser_malformed_input_smoke",
                test_config_parser_malformed_input_smoke);

    CU_pSuite suite4 = CU_add_suite("Trim functions", NULL, NULL);
    CU_add_test(suite4, "test_trim_functions", test_trim_functions);

    CU_pSuite suite5 = CU_add_suite("MQTT parser", NULL, NULL);
    CU_add_test(suite5,
                "test_mqtt_format1_slave_override",
                test_mqtt_format1_slave_override);
    CU_add_test(
        suite5, "test_mqtt_format1_no_override", test_mqtt_format1_no_override);
    CU_add_test(suite5,
                "test_mqtt_format1_reject_extra_token",
                test_mqtt_format1_reject_extra_token);
    CU_add_test(suite5,
                "test_mqtt_format1_missing_write_payload",
                test_mqtt_format1_missing_write_payload);
    CU_add_test(suite5,
                "test_mqtt_format1_serial_filter_blocks",
                test_mqtt_format1_serial_filter_blocks);
    CU_add_test(suite5,
                "test_mqtt_format1_serial_filter_allows",
                test_mqtt_format1_serial_filter_allows);
    CU_add_test(suite5,
                "test_mqtt_rejects_invalid_write_values",
                test_mqtt_rejects_invalid_write_values);
    CU_add_test(suite5,
                "test_mqtt_accepts_non_terminated_payload",
                test_mqtt_accepts_non_terminated_payload);
    CU_add_test(suite5,
                "test_mqtt_rejects_invalid_tcp_address",
                test_mqtt_rejects_invalid_tcp_address);
    CU_add_test(suite5,
                "test_mqtt_rejects_malformed_numeric_fields",
                test_mqtt_rejects_malformed_numeric_fields);
    CU_add_test(suite5,
                "test_mqtt_parser_malformed_input_smoke",
                test_mqtt_parser_malformed_input_smoke);
    CU_add_test(suite5,
                "test_mqtt_rejects_binary_or_oversized_payload",
                test_mqtt_rejects_binary_or_oversized_payload);
    CU_add_test(suite5,
                "test_mqtt_honors_qos_and_retain",
                test_mqtt_honors_qos_and_retain);

#ifdef HAVE_LUA_AUTOMATION
    CU_pSuite suite6 = CU_add_suite("Automation", NULL, NULL);
    CU_add_test(suite6, "test_automation_callbacks", test_automation_callbacks);
    CU_add_test(suite6,
                "test_automation_instruction_limit",
                test_automation_instruction_limit);
    CU_add_test(
        suite6, "test_automation_memory_limit", test_automation_memory_limit);
    CU_add_test(
        suite6, "test_automation_request_hooks", test_automation_request_hooks);
    CU_add_test(suite6,
                "test_automation_result_queue_growth",
                test_automation_result_queue_growth);
    CU_add_test(suite6,
                "test_automation_rejects_invalid_edits_and_reinitializes",
                test_automation_rejects_invalid_edits_and_reinitializes);
#else
    CU_pSuite suite6 = CU_add_suite("Automation disabled", NULL, NULL);
    CU_add_test(suite6, "test_automation_disabled", test_automation_disabled);
    CU_add_test(suite6,
                "test_automation_disabled_delivers_results",
                test_automation_disabled_delivers_results);
#endif

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    unsigned int failures = CU_get_number_of_failures();
    CU_cleanup_registry();
    close_logfile();

    return failures == 0 ? 0 : 1;
}
