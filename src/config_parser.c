#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include "config_parser.h"

uint32_t
strto_uint32(const char *str, char **endptr, int base) {
    errno = 0;
    long value = strtol(str, endptr, base);
    if (errno != 0 || value < 0 || value > UINT32_MAX) {
        errno = ERANGE;
        return UINT32_MAX;
    }
    return (uint32_t) value;
}

char *
trim(char *str, size_t len) {
    if (str == NULL || len == 0) {
        return str;
    }
    int i = 0;
    int j = len - 1;
    while (i <= j && isspace(str[i])) i++; // skip leading whitespace
    while (j >= i && isspace(str[j])) j--; // skip trailing whitespace
    str[j+1] = '\0'; // null-terminate the trimmed string
    return str+i;
}

char *
trim_left(char *str, size_t len) {
    if (str == NULL || len == 0) {
        return str; // input string is empty or null
    }
    size_t i = 0;
    while (i < len && isspace(str[i])) i++; // skip leading whitespace
    return str+i;
}

char *
trim_token(char *str, char trim_char, size_t len) {
    if (str == NULL || len == 0) {
        return str; // input string is empty or null
    }
    int i = 0;
    int j = len - 1;
    while (i <= j && str[i] == trim_char) i++; // skip leading trim_char
    while (j >= i && str[j] == trim_char) j--; // skip trailing trim_char
    str[j+1] = '\0'; // null-terminate the trimmed string
    return str+i;
}

int
config_parse_file(FILE *file, void (*callback)(void *data, rule_t *rule), void *user_obj) {
    char line[MAX_LINE_LEN];
    rule_t rule;
    int in_config = 0;
    int line_number = -1;  // -1 because of the first line, which will increment line_number to 0

    // read a line from the config file
    while (fgets(line, MAX_LINE_LEN, file) != NULL) {
    	line_number++;

		line[strcspn(line, "\n")] = 0;  // remove newline by replacing it with null byte

		line[strcspn(line, "#")] = 0;  // remove everything else after # by replacing it with null byte

		// check for start of config rule, a rule is a type and config is the accepted type
		if (strncmp(line, "config rule", 11) == 0) {
			in_config = 1;
			memset(&rule, 0, sizeof(rule_t)); // clear config struct
			continue;
		}

		// check for end of config rule
        if (in_config && line[0] == '\0') {
        	// ensure the callback function is not NULL
        	if (callback != NULL) {
        		// call the callback function
        		callback(user_obj, &rule);
			}

            in_config = 0;
            continue;
        }

		// skip empty lines in a safe way
		if (line[0] == 0) {
			continue;
		}

		// parse option
		if (in_config) {
			char *option_name = strtok(line, "=");
			char *option_value = strtok(NULL, "=");

			if (option_name == NULL || option_value == NULL) {  // check for errors
				continue;
			}

			// trim option name
			option_name = trim(option_name, strlen(option_name));

			// ensure this is a valid option element
			if (strncmp(option_name, "option", 6) != 0) {
				continue;  // skip this line
			} else {
				option_name += 6;  // move pointer to the start of the option name
			}

			// trim option name (again)
			option_name = trim(option_name, strlen(option_name));

			// trim option value
			option_value = trim(option_value, strlen(option_value));

			// option_value should be quoted, remove quotes, " or ' (leading), use trim_token
			option_value = trim_token(option_value, '\'', strlen(option_value));
			option_value = trim_token(option_value, '"', strlen(option_value));

			if (strncmp(option_name, "ip", 2) == 0) {
				// copy ip to config.ip
				strncpy(rule.ip, option_value, sizeof(rule.ip));
			} else if (strcmp(option_name, "port") == 0) {
				// parse_option_port has the following signature:
				int parse_error = parse_option_range(option_value, rule.port);
				if (parse_error != 0) {
					return CONFIG_PARSER_ERROR_INVALID_PORT;
				}
			} else if (strcmp(option_name, "slave_id") == 0) {
				rule.slave_id = atoi(option_value);
			} else if (strcmp(option_name, "function") == 0) {
				rule.function = atoi(option_value);
			} else if (strcmp(option_name, "register_address") == 0) {
				int parse_error = parse_option_range(option_value, rule.register_addr);
				if (parse_error != 0) {
					return CONFIG_PARSER_ERROR_INVALID_REGISTER_ADDRESS;
				}
			}
		}
	}

	if(in_config) {
		// execute callback function, if it is not NULL
		// otherwise the last config rule may be ignored
		// it all depends on how many \n are in the file
		if (callback != NULL) {
    		// call the callback function
    		callback(user_obj, &rule);
		}
	}

	return 0;
}

int
config_parse(char *filename, void (*callback)(void *data, rule_t *rule), void *user_obj) {
	// open file
	FILE *file = fopen(filename, "r");

	if (file == NULL) {
		return -1;
	}

	// parse file
	int error = config_parse_file(file, callback, user_obj);

	// close file
	fclose(file);

	return error;
}

// list is a list of range_u32_t, so we need to parse the option_value, and add it to the list
// the size if fixed and defined by the MAX_RANGES constant
int
parse_option_range(char *option_value, range_u32_t *list) {
	// copy option_value to a new buffer, so we can modify it, using a fixed size buffer
	char buffer[MAX_LINE_LEN];
	memset(buffer, 0, MAX_LINE_LEN);
	strncpy(buffer, option_value, MAX_LINE_LEN);

	// clear the list, just in case
	memset(list, 0, sizeof(range_u32_t) * MAX_RANGES);

	uint16_t i = 0;  // index for list

	// split option_value by comma
	char *saveptr; // for strtok_r
	char *token = strtok_r(buffer, ",", &saveptr);

	// loop through the comma separated tokens, and stop if we reach the max number of ranges
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

			errno = 0;  // reset errno
			uint32_t min = strto_uint32(token_min, NULL, 10);
			// check of overflow or underflow
			if (errno == ERANGE) {
				return PARSE_RANGE_ERROR_OVERFLOW;
			}

			errno = 0;  // reset errno
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
			errno = 0;  // reset errno

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

	// check if i is out of range, if token is not NULL, then we have more ranges than MAX_RANGES
	if (token != NULL) {
		return PARSE_RANGE_ERROR_MAX_RANGES;
	}

	return 0;
}
