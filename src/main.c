/*
 * IRCGW - Internet Relay Chat Gateway, src/main.c
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
#include "main.h"

int main(int argc, char *argv[]) {
	int ch;
	pid_t npid;

	signal(SIGINT, sigterm_handle);
	signal(SIGTERM, sigterm_handle);
	signal(SIGHUP, sighup_handle);

	debug = 0;
	config_set(CONF_FILE, DEFCONF);
	config_set(CONF_SSLCERT, DEFCERT);
	config_set(CONF_SSLKEY, DEFKEY);
	config_set(CONF_PIDFILE, DEFPID);

	while ((ch = getopt(argc, argv, "df:n")) != -1) {
		switch (ch) {
			case 'd': {
				debug++;
				break;
			}
			case 'n': {
				nofork = 1;
				break;
			}
			case 'f': {
				config_set(CONF_FILE, optarg);
				break;
			}
		}
	}

	if (chdir(DPATH)) {
		alog(LOG_ERROR, "Fail: Cannot chdir(%s): %s, check DPATH\n", DPATH, strerror(errno));
		return 2;
	}

	config_load();

	if (!nofork && (npid = fork())) {
		printf("Forking into the background as pid %d\n", (int)npid);
		exit(0);
	}

	write_pidfile();

	gw_ssl_init();

	listener_loop(print_listener);

	alog(LOG_DEBUG, "I have %d sockets!", sockets_count());

	while(1) {
		if (!sockets_check())
			break;
	}

	alog(LOG_DEBUG, "I have %d sockets!", sockets_count());

	gw_ssl_deinit();

	return 0;
}

int print_listener (struct Listener* l) {
	char *ip;
	char result[IPADDRMAXLEN];
	char *flags = listener_flags(l);

	if (IsIP6(l->sock)) {
		ip = (char *)inet_ntop(SockAF(l->sock), &SockIn6(l->sock), result, IPADDRMAXLEN);
	} else
		ip = (char *)inet_ntop(SockAF(l->sock), &SockIn(l->sock), result, IPADDRMAXLEN);

	alog(LOG_NORM, "Listener: [%s]:%d (Flags: %s)", ip, SockPort(l->sock), flags);

	return 0;
}

static void sighup_handle(int x) {
	config_load();
}

static void sigterm_handle(int x) {
	client_loop(client_del);
	listener_loop(listener_del);
}

void write_pidfile() {
	char buf[20];
	FILE* pidfd;
	int lenwrite = 0;

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "%5d\n", (int)getpid());

        if(!(pidfd = fopen(config_get(CONF_PIDFILE), "w"))) {
		alog(LOG_ERROR, "Error, unable to open pid file!");
		return;
	}

	
	lenwrite = fputs(buf, pidfd);

	fclose(pidfd);
}

