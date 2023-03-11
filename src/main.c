/*
 * This file is part of Open Modbus Gateway (omg)
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

#include "config_parser.h"
#include "filters.h"
#include "log.h"
#include "mqtt_client.h"
#include "request.h"

static int run = 1;

char clientid[24];

const char logfile_path[] = "/var/log/omg.log";
const char pidfile_path[] = "/var/run/omg.pid";

void
usage() {
    fprintf(logfile, "Usage:\n\tomg -c <configfile> [-D] [-d] [-v] [-h]\n");
    fprintf(logfile, "Options:\n");
    fprintf(logfile, "\t-c <configfile>\t\tPath to configuration file.\n");
    fprintf(logfile, "\t-D\t\t\tRun as daemon.\n");
    fprintf(logfile, "\t-d\t\t\tEnable debug mode.\n");
    fprintf(logfile, "\t-v\t\t\tEnable verbose mode.\n");
    fprintf(logfile, "\t-h\t\t\tShow this help.\n");

    exit(EXIT_FAILURE);
}

void
handle_signal(int s) {
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
    umask(0);

    // open, check and write pid to file
    fd = open(pidfile_path, O_RDONLY);
    if (fd >= 0) {
        char pidbuf[16];

        // read the contents of the PID file
        read(fd, pidbuf, sizeof(pidbuf));
        close(fd);

        // check if the process with the PID in the file is still running
        pid_t pid_from_file = atoi(pidbuf);
        if (pid_from_file > 0 && kill(pid_from_file, 0) == 0) {
            // log that the process is already running
            flog(logfile,
                 "process already running with PID %d\n",
                 pid_from_file);
            exit(EXIT_FAILURE);
        }

        // write the PID to the PID file
        fd = open(pidfile_path, O_RDWR | O_CREAT, 0640);
        if (fd < 0) {
            flog(logfile, "unable to open PID file\n");
            exit(EXIT_FAILURE);
        }

        snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
        write(fd, pidbuf, strlen(pidbuf));
        close(fd);
    } else {
        flog(logfile, "unable to open PID file\n");
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

    filter_t *filter_list = NULL;
    config_t config;
    memset(&config, 0, sizeof(config_t));

    int rc = 0;
    struct mosquitto *mosq;

    memset(clientid, 0, sizeof(clientid));
    snprintf(clientid, sizeof(clientid) - 1, "omg_%d", getpid());

    // Handle signals
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Parse command line arguments
    // -c <configfile> [-d] [-v] [-h]
    char *configfile = NULL;
    int debug = 0;
    int verbose = 0;
    int daemon = 0;

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
        default:
            usage();
            return 1;
        }
    }

    // Default values for config
    config.mqtt_protocol_version = MQTT_PROTOCOL_V311;
    config.qos = 0;
    config.retain = 0;
    config.keepalive = 60;
    config.port = 1883;
    config.timeout = 10;
    config.reconnect_delay = 5;
    config.verify_ca_cert = 1; // verify server certificate
    strncpy(config.host, "localhost", sizeof(config.host) - 1);
    strncpy(config.request_topic, "request", sizeof(config.request_topic) - 1);
    strncpy(
        config.response_topic, "response", sizeof(config.response_topic) - 1);
    strncpy(config.tls_version, "tlsv1.1", sizeof(config.tls_version) - 1);
    sprintf(config.client_id, "omg_client_%d", getpid());

    if (configfile == NULL) {
        // load config from default locations
        char *config_files[] = {"/etc/omgw/omg.conf",
                                "/etc/omgw/settings.conf",
                                "./omg.conf",
                                NULL};

        int i = 0;
        while (config_files[i] != NULL) {
            // check if the file exists
            if (access(config_files[i], F_OK) != -1) {
                if (config_parse(config_files[i], &config) == 0) {
                    break;
                }
            }
            i++;
        }

        if (config_files[i] == NULL) {
            flog(logfile, "unable to load config file\n");
            exit(EXIT_FAILURE);
        }
    } else {
        if (access(configfile, F_OK) != -1) {
            if (config_parse(configfile, &config) != 0) {
                flog(logfile, "unable to load config file\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    // validate config
    int err = validate_config(&config);
    if (err != 0) {
        flog(logfile, "invalid format of config file (%d)\n", err);
        exit(EXIT_FAILURE);
    }

    if (daemon) {
        if (daemonize() != 0) {
            flog(logfile, "unable to start as daemon\n");
            exit(EXIT_FAILURE);
        }
    }

    // set log file
    // set_logfile(logfile_path);

    if (verbose) {
        // print the loaded rules
        flog_filter(logfile, filter_list);
    }

    flog(logfile, "starting Open Modbus Gateway\n");

    // Initialize the mosquitto library
    mosquitto_lib_init();

    // Create a new mosquitto client instance
    mosq = mosquitto_new(clientid, true, &config);
    if (mosq) {
        mosquitto_threaded_set(mosq, 1); // Enable threading

        // Set callbacks
        mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
        mosquitto_message_callback_set(mosq, mqtt_message_callback);

        // Set username and password if not null in config
        if (strlen(config.username) > 0 && strlen(config.password) > 0) {
            if (mosquitto_username_pw_set(
                    mosq, config.username, config.password) !=
                MOSQ_ERR_SUCCESS) {
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

            int ret = mosquitto_tls_set(mosq, ca_cert, NULL, cert, key, NULL);
            if (ret != MOSQ_ERR_SUCCESS) {
                flog(logfile, "Unable to set TLS options\n");
                goto terminate;
            }

            // Set TLS version
            if (strlen(config.tls_version) > 0) {
                if (mosquitto_tls_opts_set(mosq, 1, config.tls_version, NULL) !=
                    MOSQ_ERR_SUCCESS) {
                    flog(logfile, "Unable to set TLS version\n");
                    goto terminate;
                }
            }

            // Verify the broker certificate
            if (config.verify_ca_cert) {
                mosquitto_tls_insecure_set(mosq, false);
            } else {
                mosquitto_tls_insecure_set(mosq, true);
            }
        }

        // MQTT protocol version
        mosquitto_opts_set(
            mosq, MOSQ_OPT_PROTOCOL_VERSION, &config.mqtt_protocol_version);

        // Connect to the broker
        rc = mosquitto_connect(mosq, config.host, config.port, 60);
        if (rc) {
            flog(logfile,
                 "Unable to connect to broker: %s\n",
                 mosquitto_strerror(rc));
            goto terminate;
        }

        // Start the main loop
        while (run) {
            rc = mosquitto_loop(mosq, -1, 1);
            if (run && rc) {
                flog(logfile, "connection error: %s\n", mosquitto_strerror(rc));
                sleep(10);
                mosquitto_reconnect(mosq);
            }
        }
    terminate:
        mosquitto_destroy(mosq);
    }

    mosquitto_lib_cleanup();

    // close log file
    if (logfile != NULL) {
        fclose(logfile);
    }

    return rc;
}
