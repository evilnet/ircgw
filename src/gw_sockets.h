/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_sockets.h
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
#ifndef GW_SOCKETS_H
#define GW_SOCKETS_H

#include "gw_common.h"
#include "gw_listener.h"
#include "gw_client.h"
#include "gw_ssl.h"

struct Socket *sockets;
fd_set fds;
int highestfd;

typedef int (*SocketLoopHandler)(struct Socket* socket);

struct Socket* socket_new();
int socket_del(struct Socket *sock);
struct Socket* socket_find(int fd);
int socket_loop (SocketLoopHandler handler);
int socket_count(struct Socket *s);
int socket_fdset(struct Socket *s);
int sockets_count();
void sockets_fdset();

int socket_bind(struct Listener *l);
int socket_connect(struct Client *c);
int socket_close_listener(struct Listener *l);
int socket_close(struct Socket *s);
struct Client* socket_accept(struct Listener *l);
char* socket_read(struct Socket *s);
int socket_write(struct Socket *s, char *in);

int sockets_check();

#endif

