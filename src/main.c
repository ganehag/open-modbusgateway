#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>

#include <modbus.h>
#include <mosquitto.h>


#define INVALID_REQUEST 1
#define ERROR_MESSAGE 2

static int run = 1;

unsigned char clientid[24];
unsigned char mqtt_host[64];
int           mqtt_port;
unsigned char mqtt_user[64];
unsigned char mqtt_pass[64];
unsigned char request_topic[256];
unsigned char response_topic[256];

typedef struct {
	struct mosquitto *mosq;

	uint8_t format;
	unsigned long long int cookie;
	uint8_t ip_type;
	char ip[64];
	char port[8];
	int timeout;
	uint8_t slave_id;
	uint8_t function;
	int register_addr;
	uint16_t register_count;
	uint16_t data[123];
} t_request;

unsigned char
*join_regs_str(const uint16_t datalen, const uint16_t *data, const char *sep) {
	unsigned char *joined = NULL;
	size_t lensep = strlen(sep);  // separator length
	size_t sz = 0;                // current size
	uint8_t is_first = TRUE;
	unsigned char buff[12];

	for(int i=0; i < datalen; i++) {
		memset(buff, 0, sizeof(buff));
		snprintf(buff, sizeof(buff), "%d", data[i]);
	        size_t len = strlen(buff);

	        // allocate/reallocate joined
        	void *tmp = realloc(joined, sz + len + (is_first == TRUE ? 0 : lensep) + 1);
	        if (!tmp) {
			// Allocation error
			return NULL;
	        }

	        joined = tmp;
	        if (is_first == FALSE) {
        	    strcpy(joined + sz, sep);
	            sz += lensep;
	        }

	        strcpy(joined + sz, buff);
	        is_first = FALSE;
	        sz += len;
	}

	return joined;
}

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
		case MOSQ_ERR_MALFORMED_UTF8:
			fprintf(stderr, "malformed reply topic\n");
		break;
		default:
			fprintf(stderr, "unknown error while publishing to broker\n");
		break;
	}
}

void
mqtt_reply_error(struct mosquitto *mosq, uint64_t cookie, int error, const char *str_msg) {
	unsigned char error_msg[256];
	memset(error_msg, 0, sizeof(error_msg));

	switch(error) {
		case INVALID_REQUEST:
			snprintf(error_msg, sizeof(error_msg), "%llu ERROR: INVALID REQUEST", cookie);
		break;
		case ERROR_MESSAGE:
			snprintf(error_msg, sizeof(error_msg), "%llu ERROR: %s", cookie, str_msg);
		break;
		default:
			snprintf(error_msg, sizeof(error_msg), "%llu ERROR: UNKNOWN", cookie);
		break;
	}

	int rc = mosquitto_publish(
		mosq,
		NULL,
		response_topic,
		strlen(error_msg),
		error_msg,
		1,
		FALSE);
	mqtt_stderr_log(rc);
}

void
mqtt_reply_ok(struct mosquitto *mosq, uint64_t cookie, uint32_t datalen, uint16_t *data) {
	unsigned char msg[1024];
	memset(msg, 0, sizeof(msg));

	if(datalen > 0) {
		unsigned char *data_str = join_regs_str(datalen, data, " ");
		snprintf(msg, sizeof(msg), "%llu OK %s", cookie, data_str);
		free(data_str);
	} else {
		snprintf(msg, sizeof(msg), "%llu OK", cookie);
	}

	int rc = mosquitto_publish(
		mosq,
		NULL,
		response_topic,
		strlen(msg),
		msg,
		1,
		FALSE);
	mqtt_stderr_log(rc);
}

void*
handle_request(void *arg) {
	modbus_t *ctx;
	t_request *req = (t_request*)arg;

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

#if DEBUG
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
	mosquitto_subscribe(mosq, NULL, request_topic, 0);
}

void
message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message) {
	/*
	* Origin: https://wiki.teltonika-networks.com/view/RUT955_Modbus#MQTT_Gateway
	*
	* 0 <COOKIE> <IP_TYPE> <IP> <PORT> <TIMEOUT> <SLAVE_ID> <MODBUS_FUNCTION> <register_addr> <REGISTER_COUNT/VALUE>
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

	int error;
	pthread_t ptid;
	t_request *req = calloc(1, sizeof(t_request));

	unsigned char *buffer = calloc(message->payloadlen + 1, sizeof(char));
	snprintf(buffer, message->payloadlen + 1, "%s", (char*) message->payload);
	buffer[message->payloadlen] = '\0';

	unsigned char raw_registers[1024];  // FIXME: can we do this in a better way?
	memset(raw_registers, 0, sizeof(raw_registers));

	int rc = sscanf(buffer, "%d %llu %d %s %s %d %d %d %d %d %s",
		&req->format,           // %d
		&req->cookie,           // %llu
		&req->ip_type,          // %d (Will be managed by modbus_new_tcp_pi)
		&req->ip,               // %s
		&req->port,             // %s (Yes, as string)
		&req->timeout,          // %d
		&req->slave_id,         // %d
		&req->function,         // %d
		&req->register_addr,    // %d (is register number in request format)
		&req->register_count,   // %d (is the value if function is 6)
		&raw_registers          // %s
	);

	free(buffer);

	switch(rc) {
		case EILSEQ:
			fprintf(stderr, "Input contains invalid character\n");
			goto cleanup;
		case EINVAL:
			fprintf(stderr, "Not enough arguments\n");
			goto cleanup;
		case ENOMEM:
			fprintf(stderr, "Out of memory\n");
			goto cleanup;
		case ERANGE:
			fprintf(stderr, "Interger size exceeds capacity\n");
			goto cleanup;
		case 9: // Number of expected items
		case 10: // or this
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
		fprintf(stderr, "Invalid format in request\n");
		goto cleanup;
	}
	if(req->ip_type < 0 || req->ip_type > 2) {
		error = INVALID_REQUEST;
		fprintf(stderr, "Invalid IP type in request\n");
		goto cleanup;
	}
	if(req->function != 1 && req->function != 2 && req->function != 3 && req->function != 4 && \
	   req->function != 5 && req->function != 6 && req->function != 15 && req->function != 16) {
		error = INVALID_REQUEST;
		fprintf(stderr, "Invalid function call in request\n");
		goto cleanup;
	}
	if(req->register_count > 123) {
		error = INVALID_REQUEST;
		fprintf(stderr, "Overflow register count in request\n");
		goto cleanup;
	}

	// Parsing of register values
	if(req->function == 5 || req->function == 6 || req->function == 15 || req->function == 16) {
		int read_count = 0;
		char* token = strtok(raw_registers, ",");

		while(token != NULL) {
			req->data[read_count] = atoi(token);
			token = strtok(NULL, ",");
			read_count++;
		}

		if(read_count != req->register_count) {
			error = INVALID_REQUEST;
			goto cleanup;
		}
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

int
main(int argc, char* argv[]) {
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


	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	mosquitto_lib_init();

	mosq = mosquitto_new(clientid, true, 0);
	if(mosq) {
		mosquitto_threaded_set(mosq, 1);  // We are using threads
		mosquitto_connect_callback_set(mosq, connect_callback);
		mosquitto_message_callback_set(mosq, message_callback);

		if (argc == 7) {
			if (mosquitto_username_pw_set(mosq, argv[5], argv[6]) != MOSQ_ERR_SUCCESS) {
				fprintf(stderr, "Wrong user or pass argument: '%s' '%s'\n", argv[5], argv[6]);
				goto terminate;
			}
		}

		rc = mosquitto_connect(mosq, mqtt_host, mqtt_port, 60);


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
