#include <stdlib.h>
#include <string.h>

#include "../src/config_parser.h"
#include "../src/filters.h"
#include "test.h"

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
                            "    option register_address '1-100'\n\n"
                            "config rule\n"
                            "    option ip '::ffff:192.168.2.1/120'\n"
                            "    option port '502, 5020-5025'\n"
                            "    option slave_id '1'\n"
                            "    option function '3'\n"
                            "    option register_address '1-100'\n\n"
                            "config rule\n"
                            "    option ip '::ffff:172.16.0.1/120'\n"
                            "    option port '5020'\n"
                            "    option slave_id '1'\n"
                            "    option function '3'\n"
                            "    option register_address '100-200'\n";

// file with single working rule
const char file_content_single[] =
    "config rule\n"
    "    option ip '::ffff:192.168.100.1/120'\n"
    "\t\t\r\voption port '502, 5020-5025'\n"
    "    option slave_id\t\t\t\t    '1'\n"
    "    option function '4'\n"
    "    option register_address '1-100,    50-200'\n";

// config file content with too many port, ranges > 8
const char file_content_too_many_port_ranges[] =
    "config rule\n"
    "    option ip '::ffff:192.168.1.1/120'\n"
    "    option port '502, 5020-5025, 5026-5030, 5031-5035, 5036-5040, "
    "5041-5045, 5046-5050, 5051-5055, 5056-5060'\n"
    "    option slave_id '1'\n"
    "    option function '3'\n"
    "    option register_address '1-100'\n\n";

const char file_content_serial_gateway[] = "config serial_gateway\n"
                                           "    option id 'ttyusb0'\n"
                                           "    option device '/dev/ttyUSB0'\n"
                                           "    option baudrate '115200'\n"
                                           "    option parity 'even'\n"
                                           "    option data_bits '8'\n"
                                           "    option stop_bits '1'\n"
                                           "    option slave_id '3'\n";

const char file_content_serial_rule[] = "config rule\n"
                                        "    option serial_id 'ttyusb0'\n"
                                        "    option slave_id '3'\n"
                                        "    option function '3'\n"
                                        "    option register_address '1-10'\n";

const char file_content_automation[] =
    "config automation\n"
    "    option script '/etc/openmmg/automation.lua'\n";

static void
config_free_lists(config_t *config) {
    filter_free(&config->head);
    serial_gateway_free(&config->serial_head);
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

    config_t config;
    memset(&config, 0, sizeof(config));

    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_PTR_NOT_NULL(config.head);

    config_free_lists(&config);

    // remove the file
    fclose(file); // not needed, but good practice
}

void
test_config_parse_single_rule(void) {
    // create a temporary file
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    // filter head to store the rules
    // write some lines to the file
    fprintf(file, "%s", file_content_single);

    // rewind the file
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));

    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);

    // check the config
    CU_ASSERT_PTR_NOT_NULL(config.head);

    iprange_t expected_cidr = {// ::ffff:192.168.100.1
                               .ipaddr = {.s6_addr = {0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0x00,
                                                      0xff,
                                                      0xff,
                                                      0xc0,
                                                      0xa8,
                                                      0x64,
                                                      0x01}},
                               .netmask = {.s6_addr = {0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0xff,
                                                       0x00}}};

    // expected port and register address results
    expected_port_reg_t exp_port_reg[] = {{
                                              {1, 502, 502},
                                              {1, 1, 100},
                                          },
                                          {
                                              {1, 502, 502},
                                              {1, 50, 200},
                                          },
                                          {
                                              {1, 5020, 5025},
                                              {1, 1, 100},
                                          },
                                          {
                                              {1, 5020, 5025},
                                              {1, 50, 200},
                                          }};

    // loop all the rules
    filter_t *current = config.head;
    int i = 0;
    while (current != NULL) {
        CU_ASSERT_EQUAL(memcmp(&current->iprange.ipaddr,
                               &expected_cidr.ipaddr,
                               sizeof(expected_cidr.ipaddr)),
                        0);
        CU_ASSERT_EQUAL(memcmp(&current->iprange.netmask,
                               &expected_cidr.netmask,
                               sizeof(expected_cidr.netmask)),
                        0);

        // check slave id
        CU_ASSERT_EQUAL(current->slave_id, 1);

        // check function code
        CU_ASSERT_EQUAL(current->function_code, 4);

        CU_ASSERT_EQUAL(current->applies_tcp, 1);
        CU_ASSERT_EQUAL(current->has_ip_range, 1);
        CU_ASSERT_EQUAL(current->has_port_range, 1);
        CU_ASSERT_EQUAL(current->applies_serial, 0);

        // compare current and expected
        CU_ASSERT_EQUAL(current->port_min, exp_port_reg[i].port.min);
        CU_ASSERT_EQUAL(current->port_max, exp_port_reg[i].port.max);
        CU_ASSERT_EQUAL(current->register_address_min,
                        exp_port_reg[i].register_addr.min);
        CU_ASSERT_EQUAL(current->register_address_max,
                        exp_port_reg[i].register_addr.max);

        current = current->next;
        i++;
    }

    // free the filter list
    config_free_lists(&config);

    // remove the file
    fclose(file); // not needed, but good practice
}

void
test_validate_config_without_rules(void) {
    config_t config;
    memset(&config, 0, sizeof(config));

    strncpy(config.host, "127.0.0.1", sizeof(config.host) - 1);
    config.port = 1883;
    config.qos = 0;
    strncpy(config.client_id, "test-client", sizeof(config.client_id) - 1);
    strncpy(config.request_topic, "request", sizeof(config.request_topic) - 1);
    strncpy(
        config.response_topic, "response", sizeof(config.response_topic) - 1);

    CU_ASSERT_EQUAL(validate_config(&config), 0);

    strncpy(
        config.response_topic, "request", sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -11);

    strncpy(
        config.request_topic, "commands/#", sizeof(config.request_topic) - 1);
    strncpy(
        config.response_topic, "responses", sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), 0);

    strncpy(config.response_topic,
            "commands/results",
            sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -11);

    strncpy(config.request_topic,
            "commands/#/invalid",
            sizeof(config.request_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -8);

    strncpy(
        config.request_topic, "commands/+", sizeof(config.request_topic) - 1);
    strncpy(config.response_topic,
            "commands/result",
            sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -11);

    strncpy(config.response_topic,
            "commands/result/detail",
            sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), 0);

    strncpy(config.request_topic, "#", sizeof(config.request_topic) - 1);
    strncpy(config.response_topic,
            "$SYS/openmmg",
            sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), 0);

    strncpy(config.request_topic, "$SYS/#", sizeof(config.request_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -11);

    strncpy(config.request_topic,
            "$share/workers/commands/#",
            sizeof(config.request_topic) - 1);
    strncpy(config.response_topic,
            "commands/result",
            sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -11);

    strncpy(config.request_topic,
            "$share/+/commands",
            sizeof(config.request_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -8);

    strncpy(config.request_topic, "commands", sizeof(config.request_topic) - 1);
    strncpy(config.response_topic,
            "responses/+",
            sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -9);

    const char invalid_utf8[] = {'b', 'a', 'd', '/', (char)0xc0, (char)0xaf, 0};
    memcpy(config.request_topic, invalid_utf8, sizeof(invalid_utf8));
    strncpy(
        config.response_topic, "response", sizeof(config.response_topic) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -8);

    const char valid_utf8[] = {'s',
                               'e',
                               'n',
                               's',
                               'o',
                               'r',
                               's',
                               '/',
                               (char)0xe2,
                               (char)0x82,
                               (char)0xac,
                               0};
    memcpy(config.request_topic, valid_utf8, sizeof(valid_utf8));
    CU_ASSERT_EQUAL(validate_config(&config), 0);

    const char control_utf8[] = {
        'r', 'e', 's', 'p', '/', (char)0xc2, (char)0x80, 0};
    memcpy(config.response_topic, control_utf8, sizeof(control_utf8));
    CU_ASSERT_EQUAL(validate_config(&config), -9);
}

void
test_validate_config_tls_options(void) {
    config_t config;
    memset(&config, 0, sizeof(config));

    strncpy(config.host, "127.0.0.1", sizeof(config.host) - 1);
    config.port = 1883;
    strncpy(config.client_id, "test-client", sizeof(config.client_id) - 1);
    strncpy(config.request_topic, "request", sizeof(config.request_topic) - 1);
    strncpy(
        config.response_topic, "response", sizeof(config.response_topic) - 1);

    strncpy(config.ca_cert_path, "ca.crt", sizeof(config.ca_cert_path) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), 0);

    memset(config.ca_cert_path, 0, sizeof(config.ca_cert_path));
    strncpy(config.cert_path, "client.crt", sizeof(config.cert_path) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -7);

    strncpy(config.ca_cert_path, "ca.crt", sizeof(config.ca_cert_path) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -7);

    strncpy(config.key_path, "client.key", sizeof(config.key_path) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), 0);

    strncpy(config.password, "secret", sizeof(config.password) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), -10);
    strncpy(config.username, "gateway", sizeof(config.username) - 1);
    CU_ASSERT_EQUAL(validate_config(&config), 0);
}

void
test_config_rejects_legacy_tls(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file,
            "config mqtt\n"
            "\toption tls_version 'tlsv1.1'\n");
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_TLS_VERSION);
    fclose(file);
}

void
test_config_parses_request_limit(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file,
            "config mqtt\n"
            "\toption max_inflight_requests '7'\n"
            "\toption reconnect_delay '3'\n");
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_EQUAL(config.max_inflight_requests, 7);
    CU_ASSERT_EQUAL(config.reconnect_delay, 3);
    fclose(file);
}

void
test_config_rejects_unknown_or_malformed_options(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file,
            "config mqtt\n"
            "\toption port_extra '1883'\n");
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config mqtt\n"
            "\toption port '1883oops'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_PORT);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config mqtt\n"
            "\toption reconnect_delay '0'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file, "option host 'localhost'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    fclose(file);
}

void
test_config_rejects_oversized_values_and_ranges(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file,
            "config mqtt\n"
            "\toption host '%0254d'\n",
            0);
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption ip '::ffff:127.0.0.1/128'\n"
            "\toption port '65536'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '1'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_PORT);
    config_free_lists(&config);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption serial_id 'ttyusb0'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '65536'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(config.head);
    CU_ASSERT_EQUAL(config.head->register_address_min, 65536U);
    CU_ASSERT_EQUAL(config.head->register_address_max, 65536U);
    config_free_lists(&config);
    fclose(file);
}

void
test_config_rejects_invalid_or_incomplete_rules(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption ip 'not_a_cidr'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '1'\n");
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_IP);
    CU_ASSERT_PTR_NULL(config.head);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption serial_id 'ttyusb0'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '0-10'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS);
    CU_ASSERT_PTR_NULL(config.head);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config serial_gateway\n"
            "\toption id 'ttyusb0'\n"
            "\toption device '/dev/ttyUSB0'\n"
            "\toption ip '127.0.0.1'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption serial_id 'ttyusb0'\n"
            "\toption function '3'\n"
            "\toption register_address '1'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_SLAVE_ID);
    CU_ASSERT_PTR_NULL(config.head);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption serial_id 'ttyusb0'\n"
            "\toption slave_id '1'\n"
            "\toption function '99'\n"
            "\toption register_address '1'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_FUNCTION_CODE);
    CU_ASSERT_PTR_NULL(config.head);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption ip '::1/128'\n"
            "\toption serial_id 'ttyusb0'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '1'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    CU_ASSERT_PTR_NULL(config.head);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption ip '::1/128'\n"
            "\toption port '0-502'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '1'\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config),
                    CONFIG_PARSER_ERROR_INVALID_PORT);
    CU_ASSERT_PTR_NULL(config.head);
    fclose(file);
}

void
test_config_allows_adjacent_sections(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config mqtt\n"
            "\toption host 'localhost'\n"
            "\n"
            "\t# Comments and blank lines may appear inside a section.\n"
            "\toption port '1883'\n"
            "config serial_gateway\n"
            "\toption id 'ttyusb0'\n"
            "\t# Keep the device option visually separate.\n"
            "\toption device '/dev/ttyUSB0'\n"
            "config rule\n"
            "\toption serial_id 'ttyusb0'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '1-10'\n");
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_STRING_EQUAL(config.host, "localhost");
    CU_ASSERT_PTR_NOT_NULL(config.serial_head);
    CU_ASSERT_PTR_NOT_NULL(config.head);
    config_free_lists(&config);
    fclose(file);
}

void
test_config_preserves_hashes_and_rejects_bad_quotes(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config mqtt\n"
            "\toption password 'abc#123' # comment\n");
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_STRING_EQUAL(config.password, "abc#123");
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config mqtt\n"
            "\toption host 'unterminated\n");
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), CONFIG_PARSER_ERROR);
    fclose(file);
}

void
test_hostname_validation_and_storage(void) {
    const char *long_hostname =
        "gateway-with-a-long-but-valid-label.example.internal.example.com";
    CU_ASSERT_TRUE(is_valid_hostname(long_hostname));
    CU_ASSERT_FALSE(is_valid_hostname("-gateway.example.com"));
    CU_ASSERT_FALSE(is_valid_hostname("gateway-.example.com"));
    CU_ASSERT_FALSE(is_valid_ipv4(NULL));
    CU_ASSERT_FALSE(is_valid_ipv6(NULL));
    CU_ASSERT_FALSE(is_valid_hostname("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaa.com"));

    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config mqtt\n"
            "\toption host '%s'\n",
            long_hostname);
    rewind(file);
    config_t config;
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_STRING_EQUAL(config.host, long_hostname);
    fclose(file);

    file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);
    fprintf(file,
            "config rule\n"
            "\toption ip '%s'\n"
            "\toption slave_id '1'\n"
            "\toption function '3'\n"
            "\toption register_address '1-10'\n",
            long_hostname);
    rewind(file);
    memset(&config, 0, sizeof(config));
    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(config.head);
    CU_ASSERT_TRUE(config.head->has_hostname);
    CU_ASSERT_STRING_EQUAL(config.head->hostname, long_hostname);

    request_t request;
    memset(&request, 0, sizeof(request));
    request.format = 0;
    request.ip_type = IP_TYPE_HOSTNAME;
    strncpy(request.ip, long_hostname, sizeof(request.ip) - 1);
    strncpy(request.port, "502", sizeof(request.port) - 1);
    request.slave_id = 1;
    request.function = 3;
    request.register_addr = 1;
    request.register_count = 1;
    CU_ASSERT_EQUAL(filter_match(config.head, &request), 0);
    strncpy(request.ip, "other.example.com", sizeof(request.ip) - 1);
    CU_ASSERT_EQUAL(filter_match(config.head, &request), -1);
    config_free_lists(&config);
    fclose(file);
}

void
test_config_parser_malformed_input_smoke(void) {
    unsigned int state = 0x12345678U;
    char input[96];

    for (size_t iteration = 0; iteration < 128; iteration++) {
        for (size_t i = 0; i < sizeof(input) - 1; i++) {
            state = state * 1103515245U + 12345U;
            input[i] = (char)(32 + (state % 95));
        }
        input[sizeof(input) - 1] = '\0';

        FILE *file = tmpfile();
        CU_ASSERT_PTR_NOT_NULL_FATAL(file);
        fputs(input, file);
        rewind(file);

        config_t config;
        memset(&config, 0, sizeof(config));
        (void)config_parse_file(file, &config);
        config_free_lists(&config);
        fclose(file);
    }
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

    config_t config;
    memset(&config, 0, sizeof(config));

    int error = config_parse_file(file, &config);

    CU_ASSERT_NOT_EQUAL(error, 0);

    config_free_lists(&config);

    // remove the file
    fclose(file); // not needed, but good practice
}

void
test_config_parse_serial_gateway(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file, "%s", file_content_serial_gateway);
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));

    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);

    serial_gateway_t *gateway = config.serial_head;
    CU_ASSERT_PTR_NOT_NULL(gateway);
    CU_ASSERT_STRING_EQUAL(gateway->id, "ttyusb0");
    CU_ASSERT_STRING_EQUAL(gateway->device, "/dev/ttyUSB0");
    CU_ASSERT_EQUAL(gateway->baudrate, 115200);
    CU_ASSERT_EQUAL(gateway->parity, 'E');
    CU_ASSERT_EQUAL(gateway->data_bits, 8);
    CU_ASSERT_EQUAL(gateway->stop_bits, 1);
    CU_ASSERT_EQUAL(gateway->slave_id, 3);

    CU_ASSERT_PTR_NULL(gateway->next);

    config_free_lists(&config);
    fclose(file);
}

void
test_config_parse_automation(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file, "%s", file_content_automation);
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));

    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);
    CU_ASSERT_STRING_EQUAL(config.automation_script,
                           "/etc/openmmg/automation.lua");

    fclose(file);
}

void
test_config_parse_serial_rule(void) {
    FILE *file = tmpfile();
    CU_ASSERT_PTR_NOT_NULL_FATAL(file);

    fprintf(file, "%s", file_content_serial_rule);
    rewind(file);

    config_t config;
    memset(&config, 0, sizeof(config));

    CU_ASSERT_EQUAL(config_parse_file(file, &config), 0);

    filter_t *rule = config.head;
    CU_ASSERT_PTR_NOT_NULL(rule);
    CU_ASSERT_EQUAL(rule->applies_serial, 1);
    CU_ASSERT_STRING_EQUAL(rule->serial_id, "ttyusb0");
    CU_ASSERT_EQUAL(rule->applies_tcp, 0);
    CU_ASSERT_EQUAL(rule->has_port_range, 0);
    CU_ASSERT_EQUAL(rule->register_address_min, 1);
    CU_ASSERT_EQUAL(rule->register_address_max, 10);

    config_free_lists(&config);
    fclose(file);
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

    char *range_8 = "0-100, 200-300, 400-500, 600-700, 800-900, 1000-1100, "
                    "1200-1300, 1400-1500";
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
    config_t config;
    memset(&config, 0, sizeof(config));

    char *options_too_many_ranges =
        "1, 2, 3, 4, 5, 6, 7, 8, 9"; // 502, 5020-5025, 5026-5030, 5031-5035,
                                     // 5036-5040, 5041-5045, 5046-5050,
                                     // 5051-5055, 5056-5060

    int error = 0;

    error = parse_option_range(options_too_many_ranges, list);

    // ensure we get an error of PARSE_RANGE_ERROR_MAX_RANGES
    CU_ASSERT_EQUAL(error, PARSE_RANGE_ERROR_MAX_RANGES);

    char options_missing_endpoint[] = "1-";
    CU_ASSERT_EQUAL(parse_option_range(options_missing_endpoint, list),
                    PARSE_RANGE_ERROR_INVALID_RANGE);

    char options_extra_endpoint[] = "1-2-3";
    CU_ASSERT_EQUAL(parse_option_range(options_extra_endpoint, list),
                    PARSE_RANGE_ERROR_INVALID_RANGE);

    char options_invalid_number[] = "12abc";
    CU_ASSERT_EQUAL(parse_option_range(options_invalid_number, list),
                    PARSE_RANGE_ERROR_INVALID_NUMBER);
    char options_leading_comma[] = ",1";
    CU_ASSERT_EQUAL(parse_option_range(options_leading_comma, list),
                    PARSE_RANGE_ERROR_INVALID_RANGE);
    char options_trailing_comma[] = "1,";
    CU_ASSERT_EQUAL(parse_option_range(options_trailing_comma, list),
                    PARSE_RANGE_ERROR_INVALID_RANGE);
    char options_empty_range[] = "1, ,2";
    CU_ASSERT_EQUAL(parse_option_range(options_empty_range, list),
                    PARSE_RANGE_ERROR_INVALID_RANGE);
    CU_ASSERT_EQUAL(parse_option_range(NULL, list),
                    PARSE_RANGE_ERROR_INVALID_RANGE);
    CU_ASSERT_EQUAL(parse_option_range(options_invalid_number, NULL),
                    PARSE_RANGE_ERROR_INVALID_RANGE);
    CU_ASSERT_EQUAL(config_parse_file(NULL, NULL), CONFIG_PARSER_ERROR);
    CU_ASSERT_EQUAL(config_parse(NULL, NULL), CONFIG_PARSER_ERROR);
    CU_ASSERT_EQUAL(config_parse("/nonexistent/openmmg/config", &config),
                    CONFIG_PARSER_ERROR_FILE_NOT_FOUND);
    CU_ASSERT_EQUAL(config_parse("/", &config), CONFIG_PARSER_ERROR);
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

    // run the tests, start by executing the trim function on all the test
    // strings the calls will modify the strings, so we need to copy the test
    // strings first
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
