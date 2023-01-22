#include "test.h"

int main() {
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
    CU_add_test(suite2, "test_multiple_filters_match", test_multiple_filters_match);
    
    CU_pSuite suite3 = CU_add_suite("Config functions", NULL, NULL);
    CU_add_test(suite3, "test_config_parse_file", test_config_parse_file);
    CU_add_test(suite3, "test_parse_option_range_ok", test_parse_option_range_ok);
    // CU_add_test(suite3, "test_parse_option_range_errors", test_parse_option_range_errors);
    CU_add_test(suite3, "test_config_file_parser_errors", test_config_file_parser_errors);
    CU_add_test(suite3, "test_config_parse_single_rule", test_config_parse_single_rule);


    CU_pSuite suite4 = CU_add_suite("Trim functions", NULL, NULL);
    CU_add_test(suite4, "test_trim_functions", test_trim_functions);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return 0;
}
