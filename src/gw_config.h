/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_config.h
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
#ifndef GW_CONFIG_H
#define GW_CONFIG_H

#include "gw_common.h"
#include "gw_listener.h"

#define CONF_SEP " \r\n"

enum ConfType {
	CONF_FILE,
	CONF_SSLCERT,
	CONF_SSLKEY,
	CONF_PIDFILE
};

int debug;
int nofork;

char *conffile;
char *sslcert;
char *sslkey;
char *pidfile;

void config_load();
void config_set(int type, char *value);
char* config_get(int type);

#endif

