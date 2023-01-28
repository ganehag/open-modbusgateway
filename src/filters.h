#ifndef FILTERS_H
#define FILTERS_H

#include <stdint.h>
#include <netinet/in.h>

#include "request.h"
#include "iprange.h"

typedef struct filter {
    iprange_t iprange;

    // Port to filter
    uint16_t port_min;
    uint16_t port_max;

    // Slave ID to filter
    uint8_t slave_id;

    // Function Code to filter
    uint8_t function_code;

    // Register Address to filter
    uint16_t register_address_min;
    uint16_t register_address_max;

    // pointer to next filter
    struct filter *next;
} filter_t;

filter_t *
filter_new(void);

// function to add filter rules to a dynamic array
void filter_add(filter_t **head, filter_t *filter);

// free the entire filter array
void filter_free(filter_t **head);

// debug print a filter
void filter_print(filter_t *filter);

// function to check if a message matches the content of request_t
int filter_match(filter_t *head, request_t *request);
int filter_match_one(filter_t *filter, request_t *request);

extern filter_t *filters;

#endif // FILTERS_H
