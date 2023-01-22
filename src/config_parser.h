#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_LINE_LEN 512
#define MAX_RANGES 8

// define some error codes
#define CONFIG_PARSER_OK 0
#define CONFIG_PARSER_ERROR -1
#define CONFIG_PARSER_ERROR_FILE_NOT_FOUND -2
#define CONFIG_PARSER_ERROR_INVALID_IP -3
#define CONFIG_PARSER_ERROR_INVALID_PORT -4
#define CONFIG_PARSER_ERROR_INVALID_SLAVE_ID -5
#define CONFIG_PARSER_ERROR_INVALID_FUNCTION_CODE -6
#define CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS -7

// error codes unique to parse_option_range()
#define PARSE_OPTION_RANGE_OK 0
// error because too many ranges are defined
#define PARSE_RANGE_ERROR_MAX_RANGES -1
// error because the range is invalid
#define PARSE_RANGE_ERROR_INVALID_RANGE -2
#define PARSE_RANGE_ERROR_INVALID_NUMBER -3
#define PARSE_RANGE_ERROR_OVERFLOW -4

typedef struct {
	uint8_t initialized;
	uint32_t min;
	uint32_t max;
} range_u32_t;

typedef struct {
	uint8_t initialized;
	uint16_t min;
	uint16_t max;
} range_u16_t;

typedef struct {
	uint8_t initialized;
	uint8_t min;
	uint8_t max;
} range_u8_t;

typedef struct {
	char ip[INET6_ADDRSTRLEN + 4]; 			// Ip address, with a CIDR prefix
	range_u32_t port[MAX_RANGES];	// Port range, 
	uint8_t slave_id;  						// The max value of a slave id in Modbus is: 247
	uint8_t function;  						// There are only 17 function codes in Modbus
	
	range_u32_t register_addr[MAX_RANGES];  // the max value of a modbus register 
	                                        // address is: 65535, which is 16 bits
	                                        // but we use 32 bits to be able to reuse the same parser
	                                        // function for both the port and register_addr
} rule_t;

char *trim_token(char *str, char trim_char, size_t len);
char *trim_left(char *str, size_t len);
char *trim(char *str, size_t len);
uint32_t strto_uint32(const char *str, char **endptr, int base);


// Parse the config file, and call the callback function for each config rule
int config_parse(char *filename, void (*callback)(void *data, rule_t *rule), void *user_obj);

int config_parse_file(FILE *file, void (*callback)(void *data, rule_t *rule), void *user_obj);

int parse_option_range(char *option_value, range_u32_t *list);



#endif
