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

#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config_parser.h"

uint32_t
strto_uint32(const char *str, char **endptr, int base) {
    errno = 0;
    long value = strtol(str, endptr, base);
    if (errno != 0 || value < 0 || value > UINT32_MAX) {
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
    int i = 0;
    int j = len - 1;
    while (i <= j && isspace(str[i]))
        i++; // skip leading whitespace
    while (j >= i && isspace(str[j]))
        j--;           // skip trailing whitespace
    str[j + 1] = '\0'; // null-terminate the trimmed string
    return str + i;
}

char *
trim_left(char *str, size_t len) {
    if (str == NULL || len == 0) {
        return str; // input string is empty or null
    }
    size_t i = 0;
    while (i < len && isspace(str[i]))
        i++; // skip leading whitespace
    return str + i;
}

char *
trim_token(char *str, char trim_char, size_t len) {
    if (str == NULL || len == 0) {
        return str; // input string is empty or null
    }
    int i = 0;
    int j = len - 1;
    while (i <= j && str[i] == trim_char)
        i++; // skip leading trim_char
    while (j >= i && str[j] == trim_char)
        j--;           // skip trailing trim_char
    str[j + 1] = '\0'; // null-terminate the trimmed string
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
    while (*end && !isspace(*end)) {
        end++;
    }

    while (*end && isspace(*end)) {
        *end++ = '\0';
    }

    if (*end) {
        *stringp = end;
    } else {
        *stringp = NULL;
    }

    return begin;
}

int
config_parse_file(FILE *file, config_t *config) {
    char line[MAX_LINE_LEN];
    rule_t rule;
    serial_gateway_t serial_gateway;

    int in_config = 0;
    int in_config_rule = 0;
    int in_config_mqtt = 0;
    int in_config_serial_gateway = 0;

    int line_number = -1; // -1 because of the first line, which will increment
                          // line_number to 0

    // default values should have been set before calling this function

    // read a line from the config file
    while (fgets(line, MAX_LINE_LEN, file) != NULL) {
        line_number++;

        // remove newline by replacing it with null byte
        line[strcspn(line, "\n")] = 0;

        // remove everything else after # by replacing it with null byte
        line[strcspn(line, "#")] = 0;

        // check for start of config rule, a rule is a type and config is the
        // accepted type
        if (strncmp(line, "config rule", 11) == 0) {
            in_config_rule = 1;
            in_config = 1;
            memset(&rule, 0, sizeof(rule_t)); // clear config struct
            continue;
        }

        if (strncmp(line, "config serial_gateway", 21) == 0) {
            in_config_serial_gateway = 1;
            in_config = 1;
            memset(&serial_gateway, 0, sizeof(serial_gateway_t));
            serial_gateway.baudrate = RTU_DEFAULT_BAUD;
            serial_gateway.parity = RTU_DEFAULT_PARITY;
            serial_gateway.data_bits = RTU_DEFAULT_DATA_BITS;
            serial_gateway.stop_bits = RTU_DEFAULT_STOP_BITS;
            continue;
        }

        // check for end of config rule
        if (in_config_rule && line[0] == '\0') {
            handle_filter_row(config, &rule);

            in_config_rule = 0;
            in_config = 0;
            continue;
        }

        if (in_config_serial_gateway && line[0] == '\0') {
            int sg_error = handle_serial_gateway_row(config, &serial_gateway);
            if (sg_error != 0) {
                return sg_error;
            }
            in_config_serial_gateway = 0;
            in_config = 0;
            continue;
        }

        // check for start of config mqtt, a rule is a type and config is the
        // accepted type
        if (strncmp(line, "config mqtt", 11) == 0) {
            in_config_mqtt = 1;
            in_config = 1;
            // FIXME: clear config struct for mqtt
            continue;
        }

        // check for end of config mqtt
        if (in_config_mqtt && line[0] == '\0') {
            in_config_mqtt = 0;
            in_config = 0;
            continue;
        }

        // skip empty lines in a safe way
        if (line[0] == 0) {
            continue;
        }

        // parse option
        if (in_config) {
            char *opt_line = trim(line, strlen(line));
            char *opt = strsep_ws(&opt_line);
            char *name = strsep_ws(&opt_line);
            char *value = opt_line;

            if (opt == NULL || name == NULL || value == NULL) {
                continue;
            }

            // trim option
            opt = trim(opt, strlen(opt));

            // ensure this is a valid option element
            if (strncmp(opt, "option", 6) != 0) {
                continue; // skip this line
            }

            name = trim(name, strlen(name));
            value = trim(value, strlen(value));

            // option_value should be quoted, remove quotes, " or ' (leading),
            // use trim_token
            value = trim_token(value, '\'', strlen(value));
            value = trim_token(value, '"', strlen(value));

            if (in_config_rule) {
                if (strncmp(name, "ip", 2) == 0) {
                    // copy ip to config.ip
                    strncpy(rule.ip, value, sizeof(rule.ip));
                } else if (strncmp(name, "port", 4) == 0) {
                    // parse_option_port has the following signature:
                    int parse_error = parse_option_range(value, rule.port);
                    if (parse_error != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_PORT;
                    }
                } else if (strncmp(name, "slave_id", 8) == 0) {
                    rule.slave_id = atoi(value);
                } else if (strncmp(name, "function", 8) == 0) {
                    rule.function = atoi(value);
                } else if (strncmp(name, "register_address", 16) == 0) {
                    int parse_error =
                        parse_option_range(value, rule.register_addr);
                    if (parse_error != 0) {
                        return CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS;
                    }
                }
            } else if (in_config_serial_gateway) {
                if (strncmp(name, "id", 2) == 0) {
                    strncpy(
                        serial_gateway.id, value, sizeof(serial_gateway.id));
                } else if (strncmp(name, "device", 6) == 0) {
                    strncpy(serial_gateway.device,
                            value,
                            sizeof(serial_gateway.device));
                } else if (strncmp(name, "ip", 2) == 0) {
                    strncpy(
                        serial_gateway.ip, value, sizeof(serial_gateway.ip));
                } else if (strncmp(name, "port", 4) == 0) {
                    errno = 0;
                    long parsed_port = strtol(value, NULL, 10);
                    if (errno != 0 || parsed_port < 0 || parsed_port > 65535) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.port = (uint16_t)parsed_port;
                } else if (strncmp(name, "baudrate", 8) == 0) {
                    int parsed_baud = atoi(value);
                    if (parsed_baud <= 0) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.baudrate = parsed_baud;
                } else if (strncmp(name, "parity", 6) == 0) {
                    char parity = toupper((unsigned char)value[0]);
                    if (strncmp(value, "none", 4) == 0) {
                        parity = 'N';
                    } else if (strncmp(value, "even", 4) == 0) {
                        parity = 'E';
                    } else if (strncmp(value, "odd", 3) == 0) {
                        parity = 'O';
                    }
                    if (parity != 'N' && parity != 'E' && parity != 'O') {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.parity = parity;
                } else if (strncmp(name, "stop_bits", 9) == 0) {
                    int parsed_stop = atoi(value);
                    if (parsed_stop != 1 && parsed_stop != 2) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.stop_bits = parsed_stop;
                } else if (strncmp(name, "data_bits", 9) == 0) {
                    int parsed_data = atoi(value);
                    if (parsed_data < 5 || parsed_data > 8) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.data_bits = parsed_data;
                } else if (strncmp(name, "slave_id", 8) == 0) {
                    int parsed_slave = atoi(value);
                    if (parsed_slave < 0 || parsed_slave > 247) {
                        return CONFIG_PARSER_ERROR_INVALID_SERIAL_GATEWAY;
                    }
                    serial_gateway.slave_id = (uint8_t)parsed_slave;
                }
            } else if (in_config_mqtt) {
                // MQTT config options
                if (strncmp(name, "host", 4) == 0) {
                    strncpy(config->host, value, sizeof(config->host));
                } else if (strncmp(name, "port", 4) == 0) {
                    config->port = atoi(value);
                } else if (strncmp(name, "keepalive", 9) == 0) {
                    config->keepalive = atoi(value);
                } else if (strncmp(name, "username", 8) == 0) {
                    strncpy(config->username, value, sizeof(config->username));
                } else if (strncmp(name, "password", 8) == 0) {
                    strncpy(config->password, value, sizeof(config->password));
                } else if (strncmp(name, "client_id", 9) == 0) {
                    strncpy(
                        config->client_id, value, sizeof(config->client_id));
                } else if (strncmp(name, "qos", 3) == 0) {
                    config->qos = atoi(value);
                } else if (strncmp(name, "retain", 6) == 0) {
                    if (strncmp(value, "true", 4) == 0 ||
                        strncmp(value, "1", 1) == 0) {
                        config->retain = 1;
                    } else if (strncmp(value, "false", 5) == 0 ||
                               strncmp(value, "0", 1) == 0) {
                        config->retain = 0;
                    }
                } else if (strncmp(name, "mqtt_protocol", 13) == 0) {
                    if (strncmp(value, "3.1", 3) == 0) {
                        config->mqtt_protocol_version = MQTT_PROTOCOL_V31;
                    } else if (strncmp(value, "3.1.1", 5) == 0) {
                        config->mqtt_protocol_version = MQTT_PROTOCOL_V311;
                    } else if (strncmp(value, "5", 1) == 0) {
                        config->mqtt_protocol_version = MQTT_PROTOCOL_V5;
                    }
                } else if (strncmp(name, "tls_version", 11) == 0) {
                    // For openssl >= 1.0.1, the available options are tlsv1.2,
                    // tlsv1.1 and tlsv1, with tlv1.2 being the default. For
                    // openssl < 1.0.1, the available options are tlsv1 and
                    // sslv3, with tlsv1 being the default.

                    if (strncmp(value, "tlsv1.2", 7) != 0 &&
                        strncmp(value, "tlsv1.1", 7) != 0 &&
                        strncmp(value, "tlsv1", 5) != 0) {
                        // skip sslv3
                        return CONFIG_PARSER_ERROR_INVALID_TLS_VERSION;
                    }

                    strncpy(config->tls_version,
                            value,
                            sizeof(config->tls_version));

                } else if (strncmp(name, "clean_session", 13) == 0) {
                    if (strncmp(value, "true", 4) == 0 ||
                        strncmp(value, "1", 1) == 0) {
                        config->clean_session = 1;
                    } else if (strncmp(value, "false", 5) == 0 ||
                               strncmp(value, "0", 1) == 0) {
                        config->clean_session = 0;
                    }
                } else if (strncmp(name, "ca_cert_path", 12) == 0) {
                    // server certificate
                    strncpy(config->ca_cert_path,
                            value,
                            sizeof(config->ca_cert_path));
                } else if (strncmp(name, "cert_path", 9) == 0) {
                    // client certificate
                    strncpy(
                        config->cert_path, value, sizeof(config->cert_path));
                } else if (strncmp(name, "key_path", 8) == 0) {
                    // client key
                    strncpy(config->key_path, value, sizeof(config->key_path));
                } else if (strncmp(name, "verify_ca_cert", 14) == 0) {
                    // verify the server certificate
                    // should not be used in production
                    if (strncmp(value, "true", 4) == 0 ||
                        strncmp(value, "1", 1) == 0) {
                        config->verify_ca_cert = 1;
                    } else if (strncmp(value, "false", 5) == 0 ||
                               strncmp(value, "0", 1) == 0) {
                        config->verify_ca_cert = 0;
                    }
                } else if (strncmp(name, "request_topic", 13) == 0) {
                    strncpy(config->request_topic,
                            value,
                            sizeof(config->request_topic));
                } else if (strncmp(name, "response_topic", 14) == 0) {
                    strncpy(config->response_topic,
                            value,
                            sizeof(config->response_topic));
                }
            }
        }
    }

    if (in_config_rule) {
        handle_filter_row(config, &rule);
    }

    if (in_config_serial_gateway) {
        int sg_error = handle_serial_gateway_row(config, &serial_gateway);
        if (sg_error != 0) {
            return sg_error;
        }
    }

    return 0;
}

int
config_parse(char *filename, config_t *config) {
    // open file
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        return -1;
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
    // copy option_value to a new buffer, so we can modify it, using a fixed
    // size buffer
    char buffer[MAX_LINE_LEN];
    memset(buffer, 0, MAX_LINE_LEN);
    strncpy(buffer, option_value, MAX_LINE_LEN);

    // clear the list, just in case
    memset(list, 0, sizeof(range_u32_t) * MAX_RANGES);

    uint16_t i = 0; // index for list

    // split option_value by comma
    char *saveptr; // for strtok_r
    char *token = strtok_r(buffer, ",", &saveptr);

    // loop through the comma separated tokens, and stop if we reach the max
    // number of ranges
    while (token != NULL && i < MAX_RANGES) {
        // start by skipping leading spaces or tabs or any other whitespace
        token = trim_left(token, strlen(token));

        // check if token is a range
        char *range = strchr(token, '-');

        if (range != NULL) {
            // token is a range
            // split token on dash
            char *token_min = strtok(token, "-");
            char *token_max = strtok(NULL, "-");

            errno = 0; // reset errno
            uint32_t min = strto_uint32(token_min, NULL, 10);
            // check of overflow or underflow
            if (errno == ERANGE) {
                return PARSE_RANGE_ERROR_OVERFLOW;
            }

            errno = 0; // reset errno
            uint32_t max = strto_uint32(token_max, NULL, 10);
            // check of overflow or underflow
            if (errno == ERANGE) {
                return PARSE_RANGE_ERROR_OVERFLOW;
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
            uint32_t number = strtoul(token, NULL, 10);

            // check for errors
            if (errno != 0) {
                return PARSE_RANGE_ERROR_INVALID_NUMBER;
            }

            // add number to list
            list[i].min = number;
            list[i].max = number;
            list[i].initialized = 1;

            // increment i
            i++;
        }

        // get next token
        token = strtok_r(NULL, ",", &saveptr);
    }

    // check if i is out of range, if token is not NULL, then we have more
    // ranges than MAX_RANGES
    if (token != NULL) {
        return PARSE_RANGE_ERROR_MAX_RANGES;
    }

    return 0;
}

void
handle_filter_row(config_t *config, rule_t *rule) {
    // loop over all the port ranges until we find a rule that is not
    // initialized
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
    // since each rule contains multiple port ranges, and multiple register
    // address ranges, we need to add the rule multiple times

    // loop over all the port ranges until we find a rule that is not
    // initialized
    for (int i = 0; i < MAX_RANGES; i++) {
        if (rule->port[i].initialized == 0) {
            break;
        }
        // loop over all the register address ranges until we find a rule that
        // is not initialized
        for (int j = 0; j < MAX_RANGES; j++) {
            if (rule->register_addr[j].initialized == 0) {
                break;
            }

            filter_t *new_filter = calloc(1, sizeof(filter_t));
            if (ip_cidr_to_in6(rule->ip, &new_filter->iprange) != 0) {
                return; // unable to parse ip
            }

            new_filter->slave_id = rule->slave_id;
            new_filter->function_code = rule->function;
            new_filter->port_min = rule->port[i].min;
            new_filter->port_max = rule->port[i].max;
            new_filter->register_address_min = rule->register_addr[j].min;
            new_filter->register_address_max = rule->register_addr[j].max;

            // add the rule to the filter
            filter_add(&config->head, new_filter);
        }
    }
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
        strncpy(existing->device, gateway->device, sizeof(existing->device));
        strncpy(existing->ip, gateway->ip, sizeof(existing->ip));
        existing->port = gateway->port;
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

    strncpy(entry->id, gateway->id, sizeof(entry->id));
    strncpy(entry->device, gateway->device, sizeof(entry->device));
    strncpy(entry->ip, gateway->ip, sizeof(entry->ip));
    entry->port = gateway->port;
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

    // if one of the tls options is set, then all of them must be set
    if (strlen(config->ca_cert_path) > 0 || strlen(config->cert_path) > 0 ||
        strlen(config->key_path) > 0) {
        if (strlen(config->ca_cert_path) == 0 ||
            strlen(config->cert_path) == 0 || strlen(config->key_path) == 0) {
            return -7;
        }
    }

    // ensure request_topic is not empty
    if (strlen(config->request_topic) == 0) {
        return -8;
    }

    // ensure response_topic is not empty
    if (strlen(config->response_topic) == 0) {
        return -9;
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
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

int
is_valid_ipv6(const char *ip) {
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, ip, &(sa.sin6_addr));
    return result != 0;
}

int
is_valid_hostname(const char *hostname) {
    // Regular expression to match hostname
    char *pattern =
        "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*(["
        "A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$";

    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        return 0;
    }

    int status = regexec(&re, hostname, 0, NULL, 0);
    regfree(&re);

    if (status != 0) {
        return 0;
    }
    return 1;
}
