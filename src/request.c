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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "request.h"

char
*join_regs_str(const uint16_t datalen, const uint16_t *data, const char *sep) {
	char *joined = NULL;
	size_t lensep = strlen(sep);  // separator length
	size_t sz = 0;                // current size
	uint8_t is_first = true;
	char buff[12];

	for(int i=0; i < datalen; i++) {
		memset(buff, 0, sizeof(buff));
		snprintf(buff, sizeof(buff), "%d", data[i]);
	        size_t len = strlen(buff);

	        // allocate/reallocate joined
        	void *tmp = realloc(joined, sz + len + (is_first == true ? 0 : lensep) + 1);
	        if (!tmp) {
				// Allocation error
				return NULL;
	        }

	        joined = tmp;
	        if (is_first == false) {
        	    strcpy(joined + sz, sep);
	            sz += lensep;
	        }

	        strcpy(joined + sz, buff);
	        is_first = false;
	        sz += len;
	}

	return joined;
}
