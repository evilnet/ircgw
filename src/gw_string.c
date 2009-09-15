/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_string.c
 * Copyright (C) 2009 Evilnet Development
 *
 * This file is part of IRCGW
 *
 * IRCGW is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IRCGW is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IRCGW.  If not, see <http://www.gnu.org/licenses/>.
 *
 * $Id:$
 */
#include "gw_string.h"

char* gw_strstripnl(char *in) {
	char *ret = strdup(in);
	int i = 0;

	for (i=0; i<strlen(ret); i++) {
		if ((ret[i] == '\r') || (ret[i] == '\n')) {
			ret[i] = '\0';
			break;
		}
	}

	return ret;
}

char* gw_strrev(char *in) {
	char *ret = strdup(in);
	int i = 0;
	int r = strlen(in) - 1;

	for (i=0; i<strlen(in); i++) {
		ret[r--] = in[i];
	}
	ret[strlen(in)] = '\0';

	return ret;
}

