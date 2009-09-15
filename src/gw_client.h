/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_client.h
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
#ifndef GW_CLIENT_H
#define GW_CLIENT_H

#include "gw_common.h"
#include "gw_listener.h"
#include "gw_sockets.h"
#include "gw_string.h"

#define CFLAG_WEBIRCSENT	0x00000001

#define CliIsWebIRCSent(c)	HasFlag(c, CFLAG_WEBIRCSENT)

#define CliSetWebIRCSent(c)	SetFlag(c, CFLAG_WEBIRCSENT)

#define CliClrWebIRCSent(c)	ClrFlag(c, CFLAG_WEBIRCSENT)

struct Client *clients;

typedef int (*ClientLoopHandler)(struct Client* client);

struct Client* client_new(struct Listener *l);
int client_del(struct Client *cli);
int client_loop(ClientLoopHandler handler);
int client_count(struct Client *c);
int client_checkfd(struct Client *c);

#endif
