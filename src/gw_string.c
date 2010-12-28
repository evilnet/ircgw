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
 * $Id$
 */
#include "gw_string.h"

char* gw_strhex(const unsigned char *raw, size_t rawsz) {
        const char *hex = "0123456789ABCDEF";
        static char hexbuf[514];
        size_t i, j;

        for (i = 0, j = 0; j < rawsz; ++j) {
                hexbuf[i++] = hex[raw[j] / 16];
                hexbuf[i++] = hex[raw[j] % 16];
        }

        hexbuf[i] = 0;
        return hexbuf;
}

