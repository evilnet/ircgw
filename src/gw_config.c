/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_config.c
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
#include "gw_config.h"

void config_load() {
	FILE* configFd;
	char tempBuf[1024];
	char *line;

	int bindc = 0;
	int delc = 0;

	char *lochost, *remhost, *wircpass, *wircsuff, *flags;
	int locport, remport;
	char *opttype, *optval;

	struct Listener *l;

	if(!(configFd = fopen(config_get(CONF_FILE), "r"))) {
		alog(LOG_ERROR, "Error, unable to open config file!");
		return;
	}

	listener_loop(listener_clearadded);

	while (!feof(configFd)) {
		line = fgets(tempBuf, 1024, configFd);

		if ((line != NULL) && (line[0] != '#')
		&& (line[0] != '\r') && (line[0] != '\n')) {
			switch(line[0]) {
				case 'p':
				case 'P': {
					strtok(line, CONF_SEP);
					lochost = strtok(NULL, CONF_SEP);
					locport = atoi(strtok(NULL, CONF_SEP));
					remhost = strtok(NULL, CONF_SEP);
					remport = atoi(strtok(NULL, CONF_SEP));
					flags = strtok(NULL, CONF_SEP);
					wircpass = strtok(NULL, CONF_SEP);
					wircsuff = strtok(NULL, CONF_SEP);

					if (!(lochost && locport && remhost && remport))
						continue;

					if ((l = listener_add(lochost, locport)) == NULL)
						continue;
					if (wircpass)
						strncpy((char *)&l->wircpass, wircpass, 255);
					if (wircsuff)
						strncpy((char *)&l->wircsuff, wircsuff, 255);

					listener_parseflags(l, flags);
					if (!listener_setremhost(l, remhost)) {
						listener_del(l);
						continue;
					}
					l->remport = remport;

					if (LstIsClosed(l))
						LstClrClosed(l);

					break;
				}
				case 'f':
				case 'F': {
					strtok(line, CONF_SEP);
					opttype = strtok(NULL, CONF_SEP);
					optval = strtok(NULL, CONF_SEP);;

					if (strcasecmp(opttype, "sslkey") == 0)
						config_set(CONF_SSLKEY, strdup(optval));
					if (strcasecmp(opttype, "sslcert") == 0)
						config_set(CONF_SSLCERT, strdup(optval));
					if (strcasecmp(opttype, "pidfile") == 0)
						config_set(CONF_PIDFILE, strdup(optval));

					break;
				}
			}
		}
	}

	FD_ZERO(&fds);

	delc = listener_loop(listener_delnoconf);
	bindc = listener_loop(listener_rebind);

	if (bindc)
		alog(LOG_DEBUG, "Bound %d listeners", bindc);
	if (delc)
		alog(LOG_DEBUG, "Removed %d listeners", delc);

	listener_loop(listener_delnobound);

	fclose(configFd);
}

void config_set(int type, char *value) {
	assert(value != NULL);

	switch (type) {
		case CONF_FILE: {
			conffile = value;
			break;
		}
		case CONF_SSLCERT: {
			sslcert = value;
			break;
		}
		case CONF_SSLKEY: {
			sslkey = value;
			break;
		}
		case CONF_PIDFILE: {
			pidfile = value;
			break;
		}
	}
}

char* config_get(int type) {
	switch (type) {
		case CONF_FILE:
			return conffile;
		case CONF_SSLCERT:
			return sslcert;
		case CONF_SSLKEY:
			return sslkey;
		case CONF_PIDFILE:
			return pidfile;
	}

	return NULL;
}

