#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#include "filters.h"

extern FILE *logfile;

void flog(FILE *stream, const char *format, ...);
void flog_filter(FILE *stream, filter_t *head);
void set_logfile(const char *path);

#endif
