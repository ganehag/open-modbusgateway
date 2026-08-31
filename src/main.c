/*
 * This file is part of Open MQTT Modbus Gateway (openmmg)
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
#include <fcntl.h>
#include <modbus/modbus.h>
#include <mosquitto.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "automation.h"
#include "config_parser.h"
#include "filters.h"
#include "log.h"
#include "mqtt_client.h"
#include "request.h"

static volatile sig_atomic_t run = 1;

const char logfile_path[] = "/var/log/openmmg.log";
const char pidfile_path[] = "/var/run/openmmg.pid";

void
usage(FILE *stream) {
    fprintf(stream, "Usage:\n\topenmmg -c <configfile> [-D] [-d] [-v] [-h]\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "\t-c <configfile>\t\tPath to configuration file.\n");
    fprintf(stream, "\t-D\t\t\tRun as daemon.\n");
    fprintf(stream, "\t-d\t\t\tEnable debug mode.\n");
    fprintf(stream, "\t-v\t\t\tEnable verbose mode.\n");
    fprintf(stream, "\t-h\t\t\tShow this help.\n");
}

void
handle_signal(int s) {
    (void)s;
    run = 0;
}

int
daemonize(void) {
    pid_t pid, sid;
    int fd;

    // fork off the parent process
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    // if we got a good PID, then we can exit the parent process
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // change the file mode mask
    umask(027);

    fd = open(pidfile_path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (fd < 0) {
        flog(logfile, "unable to open PID file\n");
        exit(EXIT_FAILURE);
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        flog(logfile, "process already running\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    char pidbuf[16] = {0};
    if (fchmod(fd, 0640) != 0 || ftruncate(fd, 0) != 0 ||
        lseek(fd, 0, SEEK_SET) < 0 ||
        snprintf(pidbuf, sizeof(pidbuf), "%d", getpid()) < 0 ||
        write(fd, pidbuf, strlen(pidbuf)) != (ssize_t)strlen(pidbuf)) {
        flog(logfile, "unable to write PID file\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    set_logfile(logfile_path);

    // create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        flog(logfile, "unable to create new SID for child process\n");
        exit(EXIT_FAILURE);
    }

    // change the current working directory
    if ((chdir("/")) < 0) {
        flog(logfile, "unable to change working directory to '/'\n");
        exit(EXIT_FAILURE);
    }

    // close out the standard file descriptors
    // close(STDIN_FILENO);
    // close(STDOUT_FILENO);
    // close(STDERR_FILENO);

    return 0;
}

int
main(int argc, char *argv[]) {
    logfile = stderr;

    config_t config;
    memset(&config, 0, sizeof(config_t));

    int rc = 0;
    int mqtt_initialized = 0;
    struct mosquitto *mosq = NULL;

    // Handle signals
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Parse command line arguments
    // -c <configfile> [-d] [-v] [-h]
    char *configfile = NULL;
    int debug = 0;
    int verbose = 0;
    int daemon = 0;
    int generated_client_id = 0;

    int c;
    while ((c = getopt(argc, argv, "c:Ddhv")) != -1) {
        switch (c) {
        case 'c':
            configfile = optarg;
            break;
        case 'D':
            daemon = true;
            break;
        case 'd':
            debug = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 1;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 1;
    }
    (void)debug;

    // Default values for config
    config.mqtt_protocol_version = MQTT_PROTOCOL_V311;
    config.qos = 0;
    config.retain = 0;
    config.clean_session = 1;
    config.keepalive = 60;
    config.port = 1883;
    config.timeout = 10;
    config.reconnect_delay = 5;
    config.max_inflight_requests = DEFAULT_MAX_INFLIGHT_REQUESTS;
    config.verify_ca_cert = 1; // verify server certificate
    strncpy(config.host, "localhost", sizeof(config.host) - 1);
    strncpy(config.request_topic, "request", sizeof(config.request_topic) - 1);
    strncpy(
        config.response_topic, "response", sizeof(config.response_topic) - 1);
    strncpy(config.tls_version, "tlsv1.2", sizeof(config.tls_version) - 1);
    if (configfile == NULL) {
        // load config from default locations
        char *config_files[] = {"/etc/openmmg/openmmg.conf",
                                "/etc/openmmg/settings.conf",
                                "./openmmg.conf",
                                NULL};

        int i = 0;
        while (config_files[i] != NULL) {
            int parse_result = config_parse(config_files[i], &config);
            if (parse_result == 0) {
                break;
            }
            if (parse_result != CONFIG_PARSER_ERROR_FILE_NOT_FOUND) {
                flog(logfile,
                     "unable to load config file '%s'\n",
                     config_files[i]);
                exit(EXIT_FAILURE);
            }
            i++;
        }

        if (config_files[i] == NULL) {
            flog(logfile, "unable to load config file\n");
            exit(EXIT_FAILURE);
        }
    } else {
        if (config_parse(configfile, &config) != 0) {
            flog(logfile, "unable to load config file\n");
            exit(EXIT_FAILURE);
        }
    }

    if (config.client_id[0] == '\0') {
        generated_client_id = 1;
        snprintf(config.client_id,
                 sizeof(config.client_id),
                 "openmmg_client_%ld",
                 (long)getpid());
    }

    // validate config
    int err = validate_config(&config);
    if (err != 0) {
        flog(logfile, "invalid format of config file (%d)\n", err);
        exit(EXIT_FAILURE);
    }
    request_set_inflight_limit(config.max_inflight_requests);

    if (automation_init(config.automation_script) != 0) {
        flog(logfile, "unable to initialize automation\n");
        exit(EXIT_FAILURE);
    }
    automation_set_config(&config);

    if (daemon) {
        if (daemonize() != 0) {
            flog(logfile, "unable to start as daemon\n");
            exit(EXIT_FAILURE);
        }
        if (generated_client_id) {
            snprintf(config.client_id,
                     sizeof(config.client_id),
                     "openmmg_client_%ld",
                     (long)getpid());
        }
    }

    // set log file
    // set_logfile(logfile_path);

    if (verbose) {
        // print the loaded rules
        flog_filter(logfile, config.head);
    }

    flog(logfile, "starting Open MQTT Modbus Gateway\n");
    automation_emit_gateway_started();

    // Initialize the mosquitto library
    rc = mosquitto_lib_init();
    if (rc != MOSQ_ERR_SUCCESS) {
        flog(logfile,
             "Unable to initialize MQTT library: %s\n",
             mosquitto_strerror(rc));
        goto shutdown;
    }
    mqtt_initialized = 1;

    // Create a new mosquitto client instance
    mosq = mosquitto_new(config.client_id, config.clean_session != 0, &config);
    if (mosq) {
        rc = mosquitto_threaded_set(mosq, 1); // Enable threading
        if (rc != MOSQ_ERR_SUCCESS) {
            flog(logfile, "Unable to enable MQTT threading\n");
            goto terminate;
        }

        // Set callbacks
        mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
        mosquitto_message_callback_set(mosq, mqtt_message_callback);

        // A username may be used with or without a password.
        if (config.username[0] != '\0') {
            const char *password =
                config.password[0] != '\0' ? config.password : NULL;
            rc = mosquitto_username_pw_set(mosq, config.username, password);
            if (rc != MOSQ_ERR_SUCCESS) {
                flog(logfile, "Unable to set username and password\n");
                goto terminate;
            }
        }

        // Set TLS options if not null in config
        if (strlen(config.ca_cert_path) > 0) {
            char *ca_cert = config.ca_cert_path;
            char *cert = NULL;
            char *key = NULL;

            // Check if cert and key are provided
            if (strlen(config.cert_path) > 0 || strlen(config.key_path) > 0) {
                if (strlen(config.cert_path) > 0 &&
                    strlen(config.key_path) > 0) {
                    cert = config.cert_path;
                    key = config.key_path;
                } else {
                    flog(logfile,
                         "Unable to set TLS options: cert and key must be "
                         "provided together\n");
                    goto terminate;
                }
            }

            rc = mosquitto_tls_set(mosq, ca_cert, NULL, cert, key, NULL);
            if (rc != MOSQ_ERR_SUCCESS) {
                flog(logfile, "Unable to set TLS options\n");
                goto terminate;
            }

            // Set TLS version
            if (strlen(config.tls_version) > 0) {
                rc = mosquitto_tls_opts_set(mosq, 1, config.tls_version, NULL);
                if (rc != MOSQ_ERR_SUCCESS) {
                    flog(logfile, "Unable to set TLS version\n");
                    goto terminate;
                }
            }

            // Verify the broker certificate
            rc = mosquitto_tls_insecure_set(mosq, !config.verify_ca_cert);
            if (rc != MOSQ_ERR_SUCCESS) {
                flog(logfile, "Unable to set TLS certificate verification\n");
                goto terminate;
            }
        }

        // MQTT protocol version
        rc = mosquitto_opts_set(
            mosq, MOSQ_OPT_PROTOCOL_VERSION, &config.mqtt_protocol_version);
        if (rc != MOSQ_ERR_SUCCESS) {
            flog(logfile, "Unable to set MQTT protocol version\n");
            goto terminate;
        }

        // Connect to the broker
        rc =
            mosquitto_connect(mosq, config.host, config.port, config.keepalive);

        // Start the main loop
        while (run) {
            if (rc == MOSQ_ERR_SUCCESS) {
                rc = mosquitto_loop(mosq, 1000, 1);
            }
            automation_dispatch_pending();
            automation_emit_timer();
            if (run && rc != MOSQ_ERR_SUCCESS) {
                flog(logfile, "connection error: %s\n", mosquitto_strerror(rc));
                automation_emit_mqtt_disconnected(mosquitto_strerror(rc));
                sleep(config.reconnect_delay);
                if (!run) {
                    break;
                }
                rc = mosquitto_reconnect(mosq);
                if (rc != MOSQ_ERR_SUCCESS) {
                    flog(logfile,
                         "reconnect error: %s\n",
                         mosquitto_strerror(rc));
                }
            }
        }
        if (!run) {
            rc = MOSQ_ERR_SUCCESS;
        }
    terminate:;
    } else {
        rc = MOSQ_ERR_NOMEM;
        flog(logfile, "Unable to create MQTT client: out of memory\n");
    }

shutdown:
    if (request_wait_for_completion(5000) != 0) {
        flog(logfile, "waiting for active Modbus requests to finish\n");
        while (request_wait_for_completion(5000) != 0) {
            flog(logfile, "still waiting for active Modbus requests\n");
        }
    }
    automation_dispatch_pending();
    if (mosq != NULL) {
        mosquitto_destroy(mosq);
    }
    if (mqtt_initialized) {
        mosquitto_lib_cleanup();
    }
    automation_emit_gateway_stopping();
    automation_shutdown();
    filter_free(&config.head);
    serial_gateway_free(&config.serial_head);

    close_logfile();

    return rc;
}
