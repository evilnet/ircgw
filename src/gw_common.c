/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_common.c
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
#include "gw_common.h"

int addrcmp(struct gwin6_addr *a, struct gwin6_addr *b, int af) {
	int match = 1;
	int i = 0;

	for (i=0; i<4; i++) {
		if ((af == AF_INET) && (i > 0))
			break;
		if (a->addr32[i] != b->addr32[i]) {
			match = 0;
		}
	}

	return match;
}

