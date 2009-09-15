/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_log.c
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
#include "gw_log.h"

char* gettimestamp(void) {
	static char buf[256];
	time_t t;
	struct tm tm;

	time(&t);
	tm = *localtime(&t);

	strftime(buf, sizeof(buf) - 1, "[%b %d %H:%M:%S %Y]", &tm);

	return (char *)buf;
}

void alog(int type, const char *fmt, ...) {
	va_list args;
	int errno_save = errno;
	char str[BUFSIZE];
	char *tbuf;

	if (fmt == NULL)
		return;

	tbuf = gettimestamp();

	va_start(args, fmt);
	vsnprintf(str, sizeof(str), fmt, args);
	va_end(args);

	if ((type == LOG_ERROR) && nofork)
		fprintf(stderr, "%s Error: %s\n", tbuf, str);
	if ((type == LOG_DEBUG) && debug && nofork)
		fprintf(stdout, "%s Debug: %s\n", tbuf, str);
	if ((type == LOG_NORM) && nofork)
		fprintf(stdout, "%s %s\n", tbuf, str);

	errno = errno_save;
}

