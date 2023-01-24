/*
 * This file is part of Open Modbus Gateway (omg) https://github.com/ganehag/open-modbusgateway.
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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include <modbus/modbus.h>
#include <mosquitto.h>

#include "request.h"
#include "filters.h"
#include "config_parser.h"


#define INVALID_REQUEST 1
#define ERROR_MESSAGE 2
#define MESSAGE_BLOCKED 3

static int run = 1;

char clientid[24];
char mqtt_host[64];
int     mqtt_port;
char mqtt_user[64];
char mqtt_pass[64];
char request_topic[256];
char response_topic[256];

void
usage() {
    fprintf(stderr, "Usage:\n\tmodbusgateway HOST PORT REQUEST_TOPIC RESPONSE_TOPIC [USER PASS]\n");
}

void
handle_signal(int s) {
    run = 0;
}

void
mqtt_stderr_log(int rc) {
    switch(rc) {
        case MOSQ_ERR_SUCCESS:
            return;
        break;
        case MOSQ_ERR_INVAL:
            fprintf(stderr, "invalid input parameters\n");
        break;
        case MOSQ_ERR_NOMEM:
            fprintf(stderr, "out of memory\n");
        break;
        case MOSQ_ERR_NO_CONN:
            fprintf(stderr, "not connected to broker\n");
        break;
        case MOSQ_ERR_PROTOCOL:
            fprintf(stderr, "protocol error while communicating with broker\n");
        break;
        case MOSQ_ERR_PAYLOAD_SIZE:
            fprintf(stderr, "payload is too large\n");
        break;
/*
        case MOSQ_ERR_MALFORMED_UTF8:
            fprintf(stderr, "malformed reply topic\n");
        break;
*/
        default:
            fprintf(stderr, "unknown error while publishing to broker\n");
        break;
    }
}

void
mqtt_reply_error(struct mosquitto *mosq, uint64_t cookie, int error, const char *str_msg) {
    char error_msg[256];
    memset(error_msg, 0, sizeof(error_msg));

    switch(error) {
        case INVALID_REQUEST:
            snprintf(error_msg, sizeof(error_msg), "%lu ERROR: INVALID REQUEST", cookie);
        break;
        case MESSAGE_BLOCKED:
            snprintf(error_msg, sizeof(error_msg), "%lu ERROR: MESSAGE BLOCKED", cookie);
        break;
        case ERROR_MESSAGE:
            snprintf(error_msg, sizeof(error_msg), "%lu ERROR: %s", cookie, str_msg);
        break;
        default:
            snprintf(error_msg, sizeof(error_msg), "%lu ERROR: UNKNOWN", cookie);
        break;
    }

    int rc = mosquitto_publish(mosq, NULL, (const char *)response_topic, strlen(error_msg), error_msg, 1, FALSE);
    mqtt_stderr_log(rc);
}

void
mqtt_reply_ok(struct mosquitto *mosq, uint64_t cookie, uint32_t datalen, uint16_t *data) {
    char msg[1024];
    memset(msg, 0, sizeof(msg));

    if(datalen > 0) {
        char *data_str = join_regs_str(datalen, data, " ");
        snprintf(msg, sizeof(msg), "%lu OK %s", cookie, data_str);
        free(data_str);
    } else {
        snprintf(msg, sizeof(msg), "%lu OK", cookie);
    }

    int rc = mosquitto_publish(mosq, NULL, (const char *)response_topic, strlen(msg), msg, 1, FALSE);
    mqtt_stderr_log(rc);
}

void*
handle_request(void *arg) {
    modbus_t *ctx;
    request_t *req = (request_t*)arg;

    // Detach from the parent thread (join not required)
    pthread_detach(pthread_self());

    // IPv4 & IPv6 support
    ctx = modbus_new_tcp_pi(req->ip, req->port);

    // Set the timeout
    modbus_set_response_timeout(ctx, req->timeout, 0);

    // Set the slave id
    modbus_set_slave(ctx, req->slave_id);

    // Perform a connect
    if(modbus_connect(ctx) == -1) {
        mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
        goto modbus_cleanup;
    } else {
        uint8_t coil_data[123];

        switch(req->function) {
            case 1:  // Read coils
                if(modbus_read_bits(ctx, req->register_addr, req->register_count, coil_data) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }
                for(int i=0; i < req->register_count; i++) {
                    req->data[i] = coil_data[i];
                }

                mqtt_reply_ok(req->mosq, req->cookie, req->register_count, req->data);
            break;
            case 2:  // Read discrete inputs
                if(modbus_read_input_bits(ctx, req->register_addr, req->register_count, coil_data) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }
                for(int i=0; i < req->register_count; i++) {
                    req->data[i] = coil_data[i];
                }

                mqtt_reply_ok(req->mosq, req->cookie, req->register_count, req->data);
            break;
            case 3:  // Read holding register
                if(modbus_read_registers(ctx, req->register_addr, req->register_count, req->data) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }

                mqtt_reply_ok(req->mosq, req->cookie, req->register_count, req->data);
            break;
            case 4:  // Read input register
                if(modbus_read_input_registers(ctx, req->register_addr, req->register_count, req->data) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }

                mqtt_reply_ok(req->mosq, req->cookie, req->register_count, req->data);
            break;
            case 5:  // Function code 5 (force/write single coil)
                if (req->register_count > 0) {
                    coil_data[0] = TRUE;
                } else {
                    coil_data[0] = FALSE;
                }

                if(modbus_write_bit(ctx, req->register_addr, coil_data[0]) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }

                mqtt_reply_ok(req->mosq, req->cookie, 0, NULL);
            break;
            case 6:  // Write single holding register
                if(modbus_write_register(ctx, req->register_addr, req->register_count) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }

                mqtt_reply_ok(req->mosq, req->cookie, 0, NULL);
            break;
            case 15:  // Function code 15 (force/write multiple coils)
                for(int i=0; i < req->register_count; i++) {
                    coil_data[i] = (req->data[i] > 0) ? TRUE : FALSE;
                }
                if(modbus_write_bits(ctx, req->register_addr, req->register_count, coil_data) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }

                mqtt_reply_ok(req->mosq, req->cookie, 0, NULL);
            break;
            case 16:  // write multiple holding registers
                if(modbus_write_registers(ctx, req->register_addr, req->register_count, req->data) == -1) {
                    mqtt_reply_error(req->mosq, req->cookie, ERROR_MESSAGE, modbus_strerror(errno));
                    goto modbus_cleanup;
                }

                mqtt_reply_ok(req->mosq, req->cookie, 0, NULL);
            break;
            default:
                mqtt_reply_error(req->mosq, req->cookie, INVALID_REQUEST, NULL);
                goto modbus_cleanup;
            break;
        }

#ifdef DEBUG
        if(req->function >= 1 && req->function <= 4) {
            for(int i = 0; i < req->register_count; i++) {
                printf("DEBUG read %02d: %i\n", i, req->data[i]);
            }
        }
#endif
    }

modbus_cleanup:

    // Modbus clean-up
    modbus_close(ctx);
    modbus_free(ctx);

    // Must free the allocated argument
    free(req);

pthread_exit:

    pthread_exit(NULL);
}

void
connect_callback(struct mosquitto *mosq, void *obj, int result) {
    mosquitto_subscribe(mosq, NULL, (char *)request_topic, 0);
}

void
flog(FILE *stream, const char *format, ...) {
    va_list args;

    // prefix the output with timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // time in rf3339 format
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%FT%T%z", t);

    va_start(args, format);
    fprintf(stream, "[%s] ", timebuf);
    vfprintf(stream, format, args);
    va_end(args);
}

void
flog_filter(FILE *stream, filter_t *head) {
    filter_t *current = head;
    while(current != NULL) {
        // prefix the output with timestamp
        time_t now = time(NULL);
        struct tm *t = localtime(&now);

        // time in rf3339 format
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%FT%T%z", t);

        // convert iprange.ipaddr to string
        char ipaddr[INET6_ADDRSTRLEN];
        memset(ipaddr, 0, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &current->iprange.ipaddr, ipaddr, INET6_ADDRSTRLEN);

        fprintf(stream, "[%s] allow rule {%s/%d:%d-%d, slave_id: %d, function_code: %d, register_address: %d-%d}\n",
            timebuf,
            ipaddr,
            in6_to_cidr_netmask(&current->iprange.netmask),
            current->port_min,
            current->port_max,
            current->slave_id,
            current->function_code,
            current->register_address_min,
            current->register_address_max
        );

        current = current->next;
    }
}


void
message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message) {
    /*
    * Origin: https://wiki.teltonika-networks.com/view/RUT955_Modbus#MQTT_Gateway
    *
    * 0 <COOKIE> <IP_TYPE> <IP> <PORT> <TIMEOUT> <SLAVE_ID> <MODBUS_FUNCTION> <REGISTER_NUMBER> <REGISTER_COUNT/VALUE>
    *
    * 0 - must be 0, which signifies a textual format (currently the only one implemented).
    * Cookie - a 64-bit unsigned integer in range [0..264]). A cookie is used in order to distinguish which response belongs
        *          to which request, each request and the corresponding response contain a matching cookie: a 64-bit unsigned integer.
    * IP type - host IP address type. Possible values:
    *   0 - IPv4 address;
    *   1 - IPv6 address;
    *   2 - hostname that will be resolved to an IP address.
    * IP - IP address of a Modbus TCP slave. IPv6 must be presented in full form (e.g., 2001:0db8:0000:0000:0000:8a2e:0370:7334).
    * Port - port number of the Modbus TCP slave.
    * Timeout - timeoutfor Modbus TCP connection, in seconds. Range [1..999].
    * Slave ID - Modbus TCP slave ID. Range [1..255].
    * Modbus function - Only these are supported at the moment:
    *   3 - read holding registers;
    *   6 - write to a single holding register;
    *   16 - write to multiple holding registers.
    * Register number - number of the first register (in range [1..65536]) from which the registers will be read/written to.
    * Register count/value - this value depends on the Modbus function:
    *   3 - register count (in range [1..125]); must not exceed the boundary (first register number + register count <= 65537);
    *   6 - register value (in range [0..65535]);
    *   16 - register count (in range [1..123]); must not exceed the boundary (first register number + register count <= 65537);
        *        and register values separated with commas, without spaces (e.g., 1,2,3,654,21,789); there must be exactly as many
        *        values as specified (with register count); each value must be in the range of [0..65535].
    */

    filter_t **head_ptr = (filter_t **) obj;
    filter_t *head = *head_ptr;

    int error = 0;
    pthread_t ptid;
    request_t *req = calloc(1, sizeof(request_t));

    char *buffer = calloc(message->payloadlen + 1, sizeof(char));
    snprintf(buffer, message->payloadlen + 1, "%s", (char*) message->payload);
    buffer[message->payloadlen] = '\0';

    char raw_registers[1024];
    memset(raw_registers, 0, sizeof(raw_registers));

    // Parse the message in a "secure" way
    int num_args = sscanf(buffer, "%hhu %llu %hhu %63s %7s %hu %hhu %hhu %u %hu %1023s",
        &req->format,           // %d
        &req->cookie,           // %llu
        &req->ip_type,          // %d (Will be managed by modbus_new_tcp_pi)
        (char *)req->ip,        // %63s
        (char*)&req->port,      // %7s
        &req->timeout,          // %d
        &req->slave_id,         // %d
        &req->function,         // %d
        &req->register_addr,    // %d (is register number in request format)
        &req->register_count,   // %d (is the value if function is 6)
        raw_registers           // %1023s
    );

#ifdef DEBUG
    flog(stderr, "num parameters %i\n", num_args);

    flog(stderr, "1: %hhu 2:%llu 3:%hhu 4:%s 5:%s 6:%hu 7:%hhu 8:%hhu 9:%u 10:%hu 11:%s\n",
        req->format,           // %d
        req->cookie,           // %llu
        req->ip_type,          // %d (Will be managed by modbus_new_tcp_pi)
        req->ip,               // %s
        req->port,             // %s (Yes, as string)
        req->timeout,          // %d
        req->slave_id,         // %d
        req->function,         // %d
        req->register_addr,    // %d (is register number in request format)
        req->register_count,   // %d (is the value if function is 6)
        raw_registers          // %s
    );
#endif

    // Check the request against the allowed filters
    if(filter_match(head, req) != 0) {
        error = MESSAGE_BLOCKED;
        flog(stderr, "Request blocked by a filter, request: %s\n", buffer);
        goto cleanup;
    }

    free(buffer);

    switch(num_args) {
        case EILSEQ:
            flog(stderr, "Input contains invalid character\n");
            goto cleanup;
        case EINVAL:
            flog(stderr, "Not enough arguments\n");
            goto cleanup;
        case ENOMEM:
            flog(stderr, "Out of memory\n");
            goto cleanup;
        case ERANGE:
            flog(stderr, "Interger size exceeds capacity\n");
            goto cleanup;
        case 10: // Number of expected items
        case 11: // or this
            break;  // break out of the switch
        default:
            goto cleanup;
    }

    // Track the pointer to mosq
    req->mosq = mosq;

    // Change from Register Number to Register Address
    // Because the request format uses number and libmodbus uses address
    req->register_addr -= 1;


    // Validate inputs
    if(req->format != 0) {
        error = INVALID_REQUEST;
        flog(stderr, "Invalid format in request\n");
        goto cleanup;
    }
    if(req->ip_type > 2) {
        error = INVALID_REQUEST;
        flog(stderr, "Invalid IP type in request\n");
        goto cleanup;
    }
    if(req->function != 1 && req->function != 2 && req->function != 3 && req->function != 4 && \
       req->function != 5 && req->function != 6 && req->function != 15 && req->function != 16) {
        error = INVALID_REQUEST;
        flog(stderr, "Invalid function call in request\n");
        goto cleanup;
    }
    if ((req->function == 15 || req->function == 16) && req->register_count > 123) {
        error = INVALID_REQUEST;
        flog(stderr, "Overflow register count in request\n");
        goto cleanup;
    }

    // Parsing of register values
    if((req->function == 15 || req->function == 16) && num_args == 11) {
        int read_count = 0;
        char* token = strtok(raw_registers, ",");

        while(token != NULL) {
            req->data[read_count] = atoi(token);
            token = strtok(NULL, ",");
            read_count++;
        }

        if(read_count != req->register_count) {
            flog(stderr, "Invalid number of values supplied\n");
            error = INVALID_REQUEST;
            goto cleanup;
        }
    } else if((req->function == 1 || req->function == 2 || req->function == 3 || req->function == 4 || \
              req->function == 5 || req->function == 6) && num_args == 10) {
        // OK
    } else {
        error = INVALID_REQUEST;
        flog(stderr, "Invalid protocol arguments\n");
        goto cleanup;
    }

    // Run the handler as a separate thread
    pthread_create(&ptid, NULL, &handle_request, req);

    goto done;

cleanup:
    mqtt_reply_error(mosq, req->cookie, error, NULL);

    // If something failed along the way
    free(req);

done:
    return;
}


void
handler(void *data, rule_t *rule) {
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

int
main(int argc, char* argv[]) {
    filter_t *filter_list = NULL;

    int rc = 0;
    struct mosquitto *mosq;

    memset(clientid, 0, sizeof(clientid));
    memset(mqtt_host, 0, sizeof(mqtt_host));
    memset(mqtt_user, 0, sizeof(mqtt_user));
    memset(mqtt_pass, 0, sizeof(mqtt_pass));
    memset(request_topic, 0, sizeof(request_topic));
    memset(response_topic, 0, sizeof(response_topic));

    snprintf(clientid, sizeof(clientid) - 1, "modbusgateway_%d", getpid());

    if(argc < 5 || argc > 7) {
        usage();
        exit(1);
    }

    snprintf(mqtt_host, sizeof(mqtt_host) - 1, "%s", argv[1]);
    mqtt_port = atoi(argv[2]);
    snprintf(request_topic, sizeof(request_topic) - 1, "%s", argv[3]);
    snprintf(response_topic, sizeof(response_topic) - 1, "%s", argv[4]);

    if(strlen(mqtt_host) == 0) {
        fprintf(stderr, "Wrong host argument: '%s'\n", mqtt_host);
        exit(1);
    }

    if(mqtt_port == 0) {
        fprintf(stderr, "Wrong port argument: '%d'\n", mqtt_port);
        exit(1);
    }

    if(strlen(request_topic) == 0 || mosquitto_sub_topic_check(request_topic) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Wrong request_topic argument: '%s'\n", request_topic);
        exit(1);
    }

    if(strlen(response_topic) == 0 || mosquitto_pub_topic_check(response_topic) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Wrong response_topic argument: '%s'\n", response_topic);
        exit(1);
    }

    // Handle signals
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // load config
    char *config_files[] = {
        "/etc/modbusgw/modbusgw.conf",
        "./modbusgw.conf",
        NULL
    };

    int i = 0;
    while(config_files[i] != NULL) {
        // check if the file exists
        if(access(config_files[i], F_OK) != -1) {
            if(config_parse(config_files[i], &handler, &filter_list) == 0) {
                break;
            }
        }
        i++;
    }

    if(config_files[i] == NULL) {
        fprintf(stderr, "Unable to load config file\n");
        exit(1);
    }

    // print the loaded rules
    flog_filter(stderr, filter_list);

    // Initialize the mosquitto library
    mosquitto_lib_init();

    // Create a new mosquitto client instance
    mosq = mosquitto_new(clientid, true, &filter_list);
    if(mosq) {
        mosquitto_threaded_set(mosq, 1);  // Enable threading

        // Set callbacks
        mosquitto_connect_callback_set(mosq, connect_callback);
        mosquitto_message_callback_set(mosq, message_callback);

        // Set username and password
        if (argc == 7) {
            if (mosquitto_username_pw_set(mosq, argv[5], argv[6]) != MOSQ_ERR_SUCCESS) {
                fprintf(stderr, "Wrong user or pass argument: '%s' '%s'\n", argv[5], argv[6]);
                goto terminate;
            }
        }

        // Connect to the broker
        rc = mosquitto_connect(mosq, mqtt_host, mqtt_port, 60);

        printf("Connecting to %s:%d\n", mqtt_host, mqtt_port);

        // Start the main loop
        while(run) {
            rc = mosquitto_loop(mosq, -1, 1);
            if(run && rc){
                printf("connection error!\n");
                sleep(10);
                mosquitto_reconnect(mosq);
            }
        }
    terminate:
        mosquitto_destroy(mosq);
    }

    mosquitto_lib_cleanup();

    return rc;
}
