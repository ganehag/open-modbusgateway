/*
 * This file is part of Open MQTT Modbus Gateway (ommg)
 * https://github.com/ganehag/open-modbusgateway.
 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config_parser.h"

uint32_t
strto_uint32(const char *str, char **endptr, int base) {
    if (str == NULL || *str == '\0') {
        errno = EINVAL;
        return UINT32_MAX;
    }

    errno = 0;
    const char *number = str;
    while (isspace((unsigned char)*number)) {
        number++;
    }
    if (*number == '-') {
        errno = ERANGE;
        if (endptr != NULL) {
            *endptr = (char *)str;
        }
        return UINT32_MAX;
    }
    unsigned long value = strtoul(str, endptr, base);
    if (errno != 0 || value > UINT32_MAX) {
        errno = ERANGE;
        return UINT32_MAX;
    }
    return (uint32_t)value;
}

char *
trim(char *str, size_t len) {
    if (str == NULL || len == 0) {
        return str;
    }
    size_t i = 0;
    size_t j = len;
    while (i < j && isspace((unsigned char)str[i]))
        i++; // skip leading whitespace
    while (j > i && isspace((unsigned char)str[j - 1]))
        j--;       // skip trailing whitespace
    str[j] = '\0'; // null-terminate the trimmed string
    return str + i;
}

char *
trim_left(char *str, size_t len) {
    if (str == NULL || len == 0) {
        return str; // input string is empty or null
    }
    size_t i = 0;
    while (i < len && isspace((unsigned char)str[i]))
        i++; // skip leading whitespace
    return str + i;
}

char *
trim_token(char *str, char trim_char, size_t len) {
    if (str == NULL || len == 0) {
        return str; // input string is empty or null
    }
    size_t i = 0;
    size_t j = len;
    while (i < j && str[i] == trim_char)
        i++; // skip leading trim_char
    while (j > i && str[j - 1] == trim_char)
        j--;       // skip trailing trim_char
    str[j] = '\0'; // null-terminate the trimmed string
    return str + i;
}

char *
strsep_ws(char **stringp) {
    char *begin, *end;
    begin = *stringp;

    if (begin == NULL) {
        return NULL;
    }

    // Find the end of the token by using isspace
    end = begin;
    while (*end && !isspace((unsigned char)*end)) {
        end++;
    }

    while (*end && isspace((unsigned char)*end)) {
        *end++ = '\0';
    }

    if (*end) {
        *stringp = end;
    } else {
        *stringp = NULL;
    }

    return begin;
}

static int
parse_uint_option(const char *value,
                  uint32_t minimum,
                  uint32_t maximum,
                  uint32_t *parsed) {
    char *end = NULL;
    uint32_t number = strto_uint32(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || number < minimum ||
        number > maximum) {
        return -1;
    }
    *parsed = number;
    return 0;
}

static int
parse_bool_option(const char *value, uint8_t *parsed) {
    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
        *parsed = 1;
        return 0;
    }
    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
        *parsed = 0;
        return 0;
    }
    return -1;
}

static int
copy_config_value(char *destination,
                  size_t destination_size,
                  const char *value) {
    size_t length = strlen(value);
    if (length >= destination_size) {
        return -1;
    }
    memcpy(destination, value, length + 1);
    return 0;
}

static void
strip_config_comment(char *line) {
    char quote = '\0';
    for (char *cursor = line; *cursor != '\0'; cursor++) {
        if (quote == '\0' && (*cursor == '\'' || *cursor == '"')) {
            quote = *cursor;
        } else if (quote != '\0' && *cursor == quote) {
            quote = '\0';
        } else if (quote == '\0' && *cursor == '#') {
            *cursor = '\0';
            return;
        }
    }
}

static char *
unquote_config_value(char *value) {
    size_t length = strlen(value);
    if (length < 2 || (value[0] != '\'' && value[0] != '"') ||
        value[length - 1] != value[0]) {
        return NULL;
    }
    value[length - 1] = '\0';
    return value + 1;
}

static int
ranges_fit(const range_u32_t *ranges, uint32_t maximum) {
    for (size_t i = 0; i < MAX_RANGES && ranges[i].initialized; i++) {
        if (ranges[i].max > maximum) {
            return 0;
        }
    }
    return 1;
}

static int
is_valid_mqtt_utf8(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;

    while (*cursor != '\0') {
        uint32_t codepoint;
        size_t length;

        if (cursor[0] <= 0x7f) {
            codepoint = cursor[0];
            length = 1;
        } else if (cursor[0] >= 0xc2 && cursor[0] <= 0xdf &&
                   (cursor[1] & 0xc0) == 0x80) {
            codepoint = ((uint32_t)(cursor[0] & 0x1f) << 6) |
                        (uint32_t)(cursor[1] & 0x3f);
            length = 2;
        } else if (cursor[0] == 0xe0 && cursor[1] >= 0xa0 &&
                   cursor[1] <= 0xbf && (cursor[2] & 0xc0) == 0x80) {
            codepoint = 0x800;
            length = 3;
        } else if (((cursor[0] >= 0xe1 && cursor[0] <= 0xec) ||
                    (cursor[0] >= 0xee && cursor[0] <= 0xef)) &&
                   (cursor[1] & 0xc0) == 0x80 && (cursor[2] & 0xc0) == 0x80) {
            codepoint = 0x800;
            length = 3;
        } else if (cursor[0] == 0xed && cursor[1] >= 0x80 &&
                   cursor[1] <= 0x9f && (cursor[2] & 0xc0) == 0x80) {
            codepoint = 0x800;
            length = 3;
        } else if (cursor[0] == 0xf0 && cursor[1] >= 0x90 &&
                   cursor[1] <= 0xbf && (cursor[2] & 0xc0) == 0x80 &&
                   (cursor[3] & 0xc0) == 0x80) {
            codepoint = 0x10000;
            length = 4;
        } else if (cursor[0] >= 0xf1 && cursor[0] <= 0xf3 &&
                   (cursor[1] & 0xc0) == 0x80 && (cursor[2] & 0xc0) == 0x80 &&
                   (cursor[3] & 0xc0) == 0x80) {
            codepoint = 0x10000;
            length = 4;
        } else if (cursor[0] == 0xf4 && cursor[1] >= 0x80 &&
                   cursor[1] <= 0x8f && (cursor[2] & 0xc0) == 0x80 &&
                   (cursor[3] & 0xc0) == 0x80) {
            codepoint = 0x10000;
            length = 4;
        } else {
            return 0;
        }

        if (codepoint <= 0x1f || (codepoint >= 0x7f && codepoint <= 0x9f)) {
            return 0;
        }
        cursor += length;
    }
    return 1;
}

static int
is_valid_mqtt_topic(const char *topic, int allow_wildcards) {
    if (topic == NULL || topic[0] == '\0' || !is_valid_mqtt_utf8(topic)) {
        return 0;
    }
    if (allow_wildcards && strncmp(topic, "$share/", 7) == 0) {
        const char *group = topic + 7;
        const char *separator = strchr(group, '/');
        if (separator == NULL || separator == group || separator[1] == '\0') {
            return 0;
        }
        for (const char *cursor = group; cursor < separator; cursor++) {
            if (*cursor == '+' || *cursor == '#') {
                return 0;
            }
        }
    }
    for (size_t i = 0; topic[i] != '\0'; i++) {
        unsigned char character = (unsigned char)topic[i];
        if (character == '#') {
            if (!allow_wildcards || (i > 0 && topic[i - 1] != '/') ||
                topic[i + 1] != '\0') {
                return 0;
            }
        } else if (character == '+') {
            if (!allow_wildcards || (i > 0 && topic[i - 1] != '/') ||
                (topic[i + 1] != '\0' && topic[i + 1] != '/')) {
                return 0;
            }
        }
    }
    return 1;
}

static int
mqtt_topic_filter_matches(const char *filter, const char *topic) {
    const char *filter_cursor = filter;
    const char *topic_cursor = topic;

    if (strncmp(filter_cursor, "$share/", 7) == 0) {
        filter_cursor = strchr(filter_cursor + 7, '/');
        if (filter_cursor == NULL) {
            return 0;
        }
        filter_cursor++;
    }

    if (topic_cursor[0] == '$' &&
        (filter_cursor[0] == '#' || filter_cursor[0] == '+')) {
        return 0;
    }

    for (;;) {
        if (*filter_cursor == '#') {
            return 1;
        }
        if (*filter_cursor == '+') {
            filter_cursor++;
            while (*topic_cursor != '\0' && *topic_cursor != '/') {
                topic_cursor++;
            }
        } else {
            while (*filter_cursor != '\0' && *filter_cursor != '/') {
                if (*topic_cursor != *filter_cursor) {
                    return 0;
                }
                filter_cursor++;
                topic_cursor++;
            }
            if (*topic_cursor != '\0' && *topic_cursor != '/') {
                return 0;
            }
        }

        if (*filter_cursor == '\0') {
            return *topic_cursor == '\0';
        }
        if (*topic_cursor == '\0') {
            return strcmp(filter_cursor, "/#") == 0;
        }
        if (*filter_cursor != '/' || *topic_cursor != '/') {
            return 0;
        }
        filter_cursor++;
        topic_cursor++;
    }
}

static int
finish_config_section(config_t *config,
                      rule_t *rule,
                      serial_gateway_t *serial_gateway,
                      int *in_config,
                      int *in_config_rule,
                      int *in_config_mqtt,
                      int *in_config_serial_gateway,
                      int *in_config_automation) {
    int error = 0;
    if (*in_config_rule) {
        error = handle_filter_row(config, rule);
    } else if (*in_config_serial_gateway) {
        error = handle_serial_gateway_row(config, serial_gateway);
    }

    *in_config = 0;
    *in_config_rule = 0;
    *in_config_mqtt = 0;
    *in_config_serial_gateway = 0;
    *in_config_automation = 0;
    return error;
}

int
config_parse_file(FILE *file, config_t *config) {
    if (file == NULL || config == NULL) {
        return CONFIG_PARSER_ERROR;
    }

    char line[MAX_LINE_LEN];
    rule_t rule;
    serial_gateway_t serial_gateway;

    int in_config = 0;
    int in_config_rule = 0;
    int in_config_mqtt = 0;
    int in_config_serial_gateway = 0;
    int in_config_automation = 0;

    int line_number = -1; // -1 because of the first line, which will increment
                          // line_number to 0

    // default values should have been set before calling this function

    // read a line from the config file
    while (fgets(line, MAX_LINE_LEN, file) != NULL) {
        line_number++;

        if (strchr(line, '\n') == NULL && !feof(file)) {
            int character;
            while ((character = fgetc(file)) != '\n' && character != EOF) {
            }
            return CONFIG_PARSER_ERROR;
        }

        // remove newline by replacing it with null byte
        line[strcspn(line, "\n")] = 0;

        strip_config_comment(line);
        char *row = trim(line, strlen(line));

        if (in_config && strncmp(row, "config ", 7) == 0) {
            int finish_error = finish_config_section(config,
                                                     &rule,
                                                     &serial_gateway,
                                                     &in_config,
                                                     &in_config_rule,
                                                     &in_config_mqtt,
                                                     &in_config_serial_gateway,
                                                     &in_config_automation);
            if (finish_error != 0) {
                return finish_error;
            }
        }

        // check for start of config rule, a rule is a type and config is the
        // accepted type
        if (strcmp(row, "config rule") == 0) {
            in_config_rule = 1;
            in_config = 1;
            memset(&rule, 0, sizeof(rule_t)); // clear config struct
            continue;
        }

        if (strcmp(row, "config serial_gateway") == 0) {
            in_config_serial_gateway = 1;
            in_config = 1;
            memset(&serial_gateway, 0, sizeof(serial_gateway_t));
            serial_gateway.baudrate = RTU_DEFAULT_BAUD;
            serial_gateway.parity = RTU_DEFAULT_PARITY;
            serial_gateway.data_bits = RTU_DEFAULT_DATA_BITS;
            serial_gateway.stop_bits = RTU_DEFAULT_STOP_BITS;
            continue;
        }

        if (strcmp(row, "config automation") == 0) {
            in_config_automation = 1;
            in_config = 1;
            continue;
        }

        // check for start of config mqtt, a rule is a type and config is the
        // accepted type
        if (strcmp(row, "config mqtt") == 0) {
            in_config_mqtt = 1;
            in_config = 1;
            continue;
        }

        if (strncmp(row, "config ", 7) == 0) {
            return CONFIG_PARSER_ERROR;
        }

        // Empty lines and comments do not terminate a section. The next
        // section declaration or EOF does that explicitly.
        if (row[0] == 0) {
            continue;
        }

        if (!in_config) {
            return CONFIG_PARSER_ERROR;
        }

        // parse option
        if (in_config) {
            char *opt_line = row;
            char *opt = strsep_ws(&opt_line);
            char *name = strsep_ws(&opt_line);
            char *value = opt_line;

            if (opt == NULL || name == NULL || value == NULL) {
                return CONFIG_PARSER_ERROR;
            }

            // trim option
            opt = trim(opt, strlen(opt));

            // ensure this is a valid option element
            if (strcmp(opt, "option") != 0) {
                return CONFIG_PARSER_ERROR;
            }

            name = trim(name, strlen(name));
            value = trim(value, strlen(value));

            value = unquote_config_value(value);
            if (value == NULL) {
                return CONFIG_PARSER_ERROR;
            }

            if (in_config_rule) {
                uint32_t number = 0;
                if (strcmp(name, "ip") == 0) {
                    if (copy_config_value(rule.ip, sizeof(rule.ip), value) !=
                        0) {
                        return CONFIG_PARSER_ERROR_INVALID_IP;
                    }
                } else if (strcmp(name, "port") == 0) {
                    // parse_option_port has the following signature:
                    int parse_error = parse_option_range(value, rule.port);
                    if (parse_error != 0 ||
                        !ranges_fit(rule.port, UINT16_MAX)) {
                        return CONFIG_PARSER_ERROR_INVALID_PORT;
                    }
                } else if (strcmp(name, "slave_id") == 0) {
                    if (parse_uint_option(value, 1, 247, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SLAVE_ID;
                    }
                    rule.slave_id = (uint8_t)number;
                } else if (strcmp(name, "function") == 0) {
                    if (parse_uint_option(value, 1, UINT8_MAX, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_FUNCTION_CODE;
                    }
                    rule.function = (uint8_t)number;
                } else if (strcmp(name, "register_address") == 0) {
                    int parse_error =
                        parse_option_range(value, rule.register_addr);
                    if (parse_error != 0 ||
                        !ranges_fit(rule.register_addr, 65536U)) {
                        return CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS;
                    }
                } else if (strcmp(name, "serial_id") == 0) {
                    if (copy_config_value(rule.serial_id,
                                          sizeof(rule.serial_id),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else {
                    return CONFIG_PARSER_ERROR;
                }
            } else if (in_config_serial_gateway) {
                uint32_t number = 0;
                if (strcmp(name, "id") == 0) {
                    if (copy_config_value(serial_gateway.id,
                                          sizeof(serial_gateway.id),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                } else if (strcmp(name, "device") == 0) {
                    if (copy_config_value(serial_gateway.device,
                                          sizeof(serial_gateway.device),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                } else if (strcmp(name, "baudrate") == 0) {
                    if (parse_uint_option(value, 1, INT_MAX, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.baudrate = (int)number;
                } else if (strcmp(name, "parity") == 0) {
                    char parity = (char)toupper((unsigned char)value[0]);
                    if (strcmp(value, "none") == 0) {
                        parity = 'N';
                    } else if (strcmp(value, "even") == 0) {
                        parity = 'E';
                    } else if (strcmp(value, "odd") == 0) {
                        parity = 'O';
                    }
                    if (parity != 'N' && parity != 'E' && parity != 'O') {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.parity = parity;
                } else if (strcmp(name, "stop_bits") == 0) {
                    if (parse_uint_option(value, 1, 2, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.stop_bits = (int)number;
                } else if (strcmp(name, "data_bits") == 0) {
                    if (parse_uint_option(value, 5, 8, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.data_bits = (int)number;
                } else if (strcmp(name, "slave_id") == 0) {
                    if (parse_uint_option(value, 0, 247, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.slave_id = (uint8_t)number;
                } else {
                    return CONFIG_PARSER_ERROR;
                }
            } else if (in_config_automation) {
                if (strcmp(name, "script") == 0) {
                    if (copy_config_value(config->automation_script,
                                          sizeof(config->automation_script),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else {
                    return CONFIG_PARSER_ERROR;
                }
            } else if (in_config_mqtt) {
                // MQTT config options
                uint32_t number = 0;
                if (strcmp(name, "host") == 0) {
                    if (copy_config_value(
                            config->host, sizeof(config->host), value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "port") == 0) {
                    if (parse_uint_option(value, 1, UINT16_MAX, &number) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_PORT;
                    }
                    config->port = (uint16_t)number;
                } else if (strcmp(name, "keepalive") == 0) {
                    if (parse_uint_option(value, 1, UINT16_MAX, &number) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                    config->keepalive = (uint16_t)number;
                } else if (strcmp(name, "reconnect_delay") == 0) {
                    if (parse_uint_option(value, 1, UINT16_MAX, &number) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                    config->reconnect_delay = (uint16_t)number;
                } else if (strcmp(name, "max_inflight_requests") == 0) {
                    char *end = NULL;
                    uint32_t limit = strto_uint32(value, &end, 10);
                    if (errno != 0 || end == value || *end != '\0' ||
                        limit == 0 || limit > UINT16_MAX) {
                        return CONFIG_PARSER_ERROR;
                    }
                    config->max_inflight_requests = (uint16_t)limit;
                } else if (strcmp(name, "username") == 0) {
                    if (copy_config_value(config->username,
                                          sizeof(config->username),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "password") == 0) {
                    if (copy_config_value(config->password,
                                          sizeof(config->password),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "client_id") == 0) {
                    if (copy_config_value(config->client_id,
                                          sizeof(config->client_id),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "qos") == 0) {
                    if (parse_uint_option(value, 0, 2, &number) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                    config->qos = (uint8_t)number;
                } else if (strcmp(name, "retain") == 0) {
                    if (parse_bool_option(value, &config->retain) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "mqtt_protocol") == 0) {
                    if (strcmp(value, "3.1") == 0) {
                        config->mqtt_protocol_version = MQTT_PROTOCOL_V31;
                    } else if (strcmp(value, "3.1.1") == 0) {
                        config->mqtt_protocol_version = MQTT_PROTOCOL_V311;
                    } else if (strcmp(value, "5") == 0) {
                        config->mqtt_protocol_version = MQTT_PROTOCOL_V5;
                    } else {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "tls_version") == 0) {
                    if (strcmp(value, "tlsv1.2") != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_TLS_VERSION;
                    }

                    if (copy_config_value(config->tls_version,
                                          sizeof(config->tls_version),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_TLS_VERSION;
                    }

                } else if (strcmp(name, "clean_session") == 0) {
                    if (parse_bool_option(value, &config->clean_session) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "ca_cert_path") == 0) {
                    // server certificate
                    if (copy_config_value(config->ca_cert_path,
                                          sizeof(config->ca_cert_path),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "cert_path") == 0) {
                    // client certificate
                    if (copy_config_value(config->cert_path,
                                          sizeof(config->cert_path),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "key_path") == 0) {
                    // client key
                    if (copy_config_value(config->key_path,
                                          sizeof(config->key_path),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "verify_ca_cert") == 0) {
                    // verify the server certificate
                    // should not be used in production
                    if (parse_bool_option(value, &config->verify_ca_cert) !=
                        0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "request_topic") == 0) {
                    if (copy_config_value(config->request_topic,
                                          sizeof(config->request_topic),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else if (strcmp(name, "response_topic") == 0) {
                    if (copy_config_value(config->response_topic,
                                          sizeof(config->response_topic),
                                          value) != 0) {
                        return CONFIG_PARSER_ERROR;
                    }
                } else {
                    return CONFIG_PARSER_ERROR;
                }
            }
        }
    }

    if (ferror(file)) {
        return CONFIG_PARSER_ERROR;
    }

    if (in_config) {
        return finish_config_section(config,
                                     &rule,
                                     &serial_gateway,
                                     &in_config,
                                     &in_config_rule,
                                     &in_config_mqtt,
                                     &in_config_serial_gateway,
                                     &in_config_automation);
    }

    return 0;
}

int
config_parse(const char *filename, config_t *config) {
    if (filename == NULL || config == NULL) {
        return CONFIG_PARSER_ERROR;
    }
    // open file
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        return errno == ENOENT || errno == ENOTDIR
                   ? CONFIG_PARSER_ERROR_FILE_NOT_FOUND
                   : CONFIG_PARSER_ERROR;
    }

    // parse file
    int error = config_parse_file(file, config);

    // close file
    fclose(file);

    return error;
}

// list is a list of range_u32_t, so we need to parse the option_value, and add
// it to the list the size if fixed and defined by the MAX_RANGES constant
int
parse_option_range(char *option_value, range_u32_t *list) {
    if (option_value == NULL || list == NULL) {
        return PARSE_RANGE_ERROR_INVALID_RANGE;
    }
    if (strlen(option_value) >= MAX_LINE_LEN) {
        return PARSE_RANGE_ERROR_INVALID_RANGE;
    }
    // copy option_value to a new buffer, so we can modify it, using a fixed
    // size buffer
    char buffer[MAX_LINE_LEN];
    memset(buffer, 0, MAX_LINE_LEN);
    strncpy(buffer, option_value, sizeof(buffer) - 1);

    // clear the list, just in case
    memset(list, 0, sizeof(range_u32_t) * MAX_RANGES);

    uint16_t i = 0; // index for list
    char *token = buffer;

    for (;;) {
        char *separator = strchr(token, ',');
        if (separator != NULL) {
            *separator = '\0';
        }

        token = trim(token, strlen(token));
        if (token[0] == '\0') {
            return PARSE_RANGE_ERROR_INVALID_RANGE;
        }
        if (i >= MAX_RANGES) {
            return PARSE_RANGE_ERROR_MAX_RANGES;
        }

        // check if token is a range
        char *range = strchr(token, '-');

        if (range != NULL) {
            // token is a range
            if (strchr(range + 1, '-') != NULL) {
                return PARSE_RANGE_ERROR_INVALID_RANGE;
            }
            *range = '\0';
            char *token_min = trim(token, strlen(token));
            char *token_max = trim(range + 1, strlen(range + 1));
            if (token_min[0] == '\0' || token_max[0] == '\0') {
                return PARSE_RANGE_ERROR_INVALID_RANGE;
            }

            errno = 0; // reset errno
            char *end = NULL;
            uint32_t min = strto_uint32(token_min, &end, 10);
            // check of overflow or underflow
            if (errno == ERANGE) {
                return PARSE_RANGE_ERROR_OVERFLOW;
            }
            if (errno != 0 || end == token_min || *end != '\0') {
                return PARSE_RANGE_ERROR_INVALID_RANGE;
            }

            errno = 0; // reset errno
            end = NULL;
            uint32_t max = strto_uint32(token_max, &end, 10);
            // check of overflow or underflow
            if (errno == ERANGE) {
                return PARSE_RANGE_ERROR_OVERFLOW;
            }
            if (errno != 0 || end == token_max || *end != '\0') {
                return PARSE_RANGE_ERROR_INVALID_RANGE;
            }

            // check for errors
            if (errno != 0 || min > max) {
                return PARSE_RANGE_ERROR_INVALID_RANGE;
            }

            // add range to list
            list[i].min = min;
            list[i].max = max;
            list[i].initialized = 1;

            // increment i
            i++;
        } else {
            errno = 0; // reset errno

            // token is a single number
            char *end = NULL;
            uint32_t number = strto_uint32(token, &end, 10);

            // check for errors
            if (errno == ERANGE) {
                return PARSE_RANGE_ERROR_OVERFLOW;
            }
            if (errno != 0 || end == token || *end != '\0') {
                return PARSE_RANGE_ERROR_INVALID_NUMBER;
            }

            // add number to list
            list[i].min = number;
            list[i].max = number;
            list[i].initialized = 1;

            // increment i
            i++;
        }

        if (separator == NULL) {
            break;
        }
        token = separator + 1;
    }

    return 0;
}

int
handle_filter_row(config_t *config, const rule_t *rule) {
    // add the rule to the filter, so we can check it later
    // since each rule contains multiple port ranges, and multiple register
    // address ranges, we need to add the rule multiple times

    if (config == NULL || rule == NULL) {
        return CONFIG_PARSER_ERROR;
    }

    int has_ip = (rule->ip[0] != '\0');
    int has_serial = (rule->serial_id[0] != '\0');

    int port_count = 0;
    for (int i = 0; i < MAX_RANGES; i++) {
        if (rule->port[i].initialized == 0) {
            break;
        }
        if (rule->port[i].min == 0 || rule->port[i].min > rule->port[i].max ||
            rule->port[i].max > UINT16_MAX) {
            return CONFIG_PARSER_ERROR_INVALID_PORT;
        }
        port_count++;
    }

    int register_count = 0;
    for (int i = 0; i < MAX_RANGES; i++) {
        if (rule->register_addr[i].initialized == 0) {
            break;
        }
        if (rule->register_addr[i].min == 0 ||
            rule->register_addr[i].min > rule->register_addr[i].max ||
            rule->register_addr[i].max > 65536U) {
            return CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS;
        }
        register_count++;
    }

    if (has_ip == has_serial) {
        return CONFIG_PARSER_ERROR;
    }
    if (rule->slave_id == 0) {
        return CONFIG_PARSER_ERROR_INVALID_SLAVE_ID;
    }
    if (rule->function != 1 && rule->function != 2 && rule->function != 3 &&
        rule->function != 4 && rule->function != 5 && rule->function != 6 &&
        rule->function != 15 && rule->function != 16) {
        return CONFIG_PARSER_ERROR_INVALID_FUNCTION_CODE;
    }
    if (register_count == 0) {
        return CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS;
    }
    if (port_count > 0 && !has_ip) {
        return CONFIG_PARSER_ERROR_INVALID_PORT;
    }

    if (port_count == 0) {
        port_count = 1;
    }

    iprange_t parsed_iprange;
    int target_is_hostname = 0;
    if (has_ip && ip_cidr_to_in6(rule->ip, &parsed_iprange) != 0) {
        if (!is_valid_hostname(rule->ip)) {
            return CONFIG_PARSER_ERROR_INVALID_IP;
        }
        target_is_hostname = 1;
    }

    filter_t *new_head = NULL;
    for (int i = 0; i < port_count; i++) {
        uint16_t port_min = 0;
        uint16_t port_max = 0;
        uint8_t has_port_range = 0;

        if (i < MAX_RANGES && rule->port[i].initialized != 0) {
            port_min = (uint16_t)rule->port[i].min;
            port_max = (uint16_t)rule->port[i].max;
            has_port_range = 1;
        }

        for (int j = 0; j < register_count; j++) {
            filter_t *new_filter = filter_new();
            if (new_filter == NULL) {
                filter_free(&new_head);
                return CONFIG_PARSER_ERROR;
            }

            new_filter->slave_id = rule->slave_id;
            new_filter->function_code = rule->function;
            new_filter->register_address_min = rule->register_addr[j].min;
            new_filter->register_address_max = rule->register_addr[j].max;
            new_filter->port_min = port_min;
            new_filter->port_max = port_max;
            new_filter->has_port_range = has_port_range;

            if (has_ip) {
                new_filter->applies_tcp = 1;
                if (target_is_hostname) {
                    new_filter->has_hostname = 1;
                    memcpy(
                        new_filter->hostname, rule->ip, strlen(rule->ip) + 1);
                } else {
                    new_filter->has_ip_range = 1;
                    new_filter->iprange = parsed_iprange;
                }
            }

            if (has_serial) {
                new_filter->applies_serial = 1;
                strncpy(new_filter->serial_id,
                        rule->serial_id,
                        sizeof(new_filter->serial_id));
                new_filter->serial_id[sizeof(new_filter->serial_id) - 1] = '\0';
            }

            if (!new_filter->applies_tcp && !new_filter->applies_serial) {
                free(new_filter);
                filter_free(&new_head);
                return CONFIG_PARSER_ERROR;
            }

            filter_add(&new_head, new_filter);
        }
    }

    while (new_head != NULL) {
        filter_t *next = new_head->next;
        new_head->next = NULL;
        filter_add(&config->head, new_head);
        new_head = next;
    }
    return 0;
}

int
handle_serial_gateway_row(config_t *config, serial_gateway_t *gateway) {
    if (config == NULL || gateway == NULL) {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    if (strlen(gateway->id) == 0 || strlen(gateway->device) == 0) {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    if (gateway->baudrate <= 0) {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    if (gateway->parity != 'N' && gateway->parity != 'E' &&
        gateway->parity != 'O') {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    if (gateway->data_bits < 5 || gateway->data_bits > 8) {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    if (gateway->stop_bits != 1 && gateway->stop_bits != 2) {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    if (gateway->slave_id > 247) {
        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
    }

    serial_gateway_t *existing =
        serial_gateway_find(config->serial_head, gateway->id);

    if (existing != NULL) {
        memcpy(existing->device, gateway->device, sizeof(existing->device));
        existing->baudrate = gateway->baudrate;
        existing->parity = gateway->parity;
        existing->data_bits = gateway->data_bits;
        existing->stop_bits = gateway->stop_bits;
        existing->slave_id = gateway->slave_id;
        return 0;
    }

    serial_gateway_t *entry = calloc(1, sizeof(serial_gateway_t));
    if (entry == NULL) {
        return CONFIG_PARSER_ERROR;
    }

    memcpy(entry->id, gateway->id, sizeof(entry->id));
    memcpy(entry->device, gateway->device, sizeof(entry->device));
    entry->baudrate = gateway->baudrate;
    entry->parity = gateway->parity;
    entry->data_bits = gateway->data_bits;
    entry->stop_bits = gateway->stop_bits;
    entry->slave_id = gateway->slave_id;

    entry->next = NULL;

    if (config->serial_head == NULL) {
        config->serial_head = entry;
    } else {
        serial_gateway_t *current = config->serial_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = entry;
    }

    return 0;
}

int
validate_config(config_t *config) {
    // check if config is NULL
    if (config == NULL) {
        return -1;
    }

    int valid_ipv4 = is_valid_ipv4(config->host);
    int valid_ipv6 = is_valid_ipv6(config->host);
    int valid_hostname = is_valid_hostname(config->host);

    // if all of them are false, then the hostname is invalid
    if (!valid_hostname && !valid_ipv4 && !valid_ipv6) {
        return -3;
    }

    if (config->port == 0) {
        return -4;
    }

    // ensure client id is not empty
    if (strlen(config->client_id) == 0) {
        return -5;
    }

    // ensure qos is between 0 and 2
    if (config->qos > 2) {
        return -6;
    }

    if (config->password[0] != '\0' && config->username[0] == '\0') {
        return -10;
    }

    // A CA certificate enables server-only TLS. Client credentials are
    // optional, but must be supplied together and require a CA certificate.
    if (strlen(config->cert_path) > 0 || strlen(config->key_path) > 0) {
        if (strlen(config->ca_cert_path) == 0 ||
            strlen(config->cert_path) == 0 || strlen(config->key_path) == 0) {
            return -7;
        }
    }

    if (!is_valid_mqtt_topic(config->request_topic, 1)) {
        return -8;
    }

    if (!is_valid_mqtt_topic(config->response_topic, 0)) {
        return -9;
    }

    if (mqtt_topic_filter_matches(config->request_topic,
                                  config->response_topic)) {
        return -11;
    }

    return 0;
}

serial_gateway_t *
serial_gateway_find(serial_gateway_t *head, const char *id) {
    if (id == NULL) {
        return NULL;
    }

    serial_gateway_t *current = head;
    while (current != NULL) {
        if (strcmp(current->id, id) == 0) {
            return current;
        }
        current = current->next;
    }

    return NULL;
}

void
serial_gateway_free(serial_gateway_t **head) {
    if (head == NULL || *head == NULL) {
        return;
    }

    serial_gateway_t *current = *head;
    serial_gateway_t *next = NULL;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }

    *head = NULL;
}

int
is_valid_ipv4(const char *ip) {
    if (ip == NULL) {
        return 0;
    }
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

int
is_valid_ipv6(const char *ip) {
    if (ip == NULL) {
        return 0;
    }
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ip, &(sa.sin6_addr));
    return result != 0;
}

int
is_valid_hostname(const char *hostname) {
    if (hostname == NULL) {
        return 0;
    }
    size_t length = strlen(hostname);
    if (length == 0 || length > 253) {
        return 0;
    }

    size_t label_length = 0;
    for (size_t i = 0; i <= length; i++) {
        unsigned char character = (unsigned char)hostname[i];
        if (character == '.' || character == '\0') {
            if (label_length == 0 || label_length > 63 ||
                hostname[i - 1] == '-') {
                return 0;
            }
            label_length = 0;
        } else {
            if (!isalnum(character) && character != '-') {
                return 0;
            }
            if (label_length == 0 && character == '-') {
                return 0;
            }
            label_length++;
        }
    }
    return 1;
}
