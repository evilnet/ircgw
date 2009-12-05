/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_listener.c
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
#include "gw_listener.h"

struct Listener* listener_add(char *addr, int port) {
	struct Listener *new;

	new = listener_find(addr, port);

	if (new != NULL) {
		LstSetAdded(new);
		return new;
	}

	new = malloc(sizeof(struct Listener));
	alog(LOG_DEBUG, "Lst: new()");

	new->sock = socket_new();

	new->sock->af = AF_INET;
	if (inet_pton(AF_INET, addr, &new->sock->addr) <= 0) {
		new->sock->af = AF_INET6;
		if (inet_pton(AF_INET6, addr, &new->sock->addr6) <= 0) {
			socket_del(new->sock);
			free(new);
			return NULL;
		}
	}

	new->flags = 0;
	new->clients = 0;
	LstSetAdded(new);
	new->sock->port = port;
	new->prev = NULL;
	if (listeners != NULL)
		listeners->prev = new;
	new->next = listeners;
	listeners = new;

	return new;
}

int listener_del(struct Listener* l) {
	assert(l != NULL);

	if (l->clients) {
		LstSetClosed(l);
		return 0;
	}

	socket_close_listener(l);

	free(l->wircpass);
	free(l->wircsuff);

	if (l->next != NULL)
		l->next->prev = l->prev;
	if (l->prev == NULL)
		listeners = l->next;
	else
		l->prev->next = l->next;

	alog(LOG_DEBUG, "Lst free()");
	free(l);
	return 1;
}

struct Listener* listener_find(char *addr, int port) {
	struct Listener *l;
	struct gwin6_addr ip;
	int m = 0;

	for (l = listeners; l != NULL; l = l->next) {
		if (inet_pton(l->sock->af, addr, &ip) <= 0)
			continue;

		if (port == l->sock->port)
			m = 1;
		if (IsIP6(l->sock)) {
			if (!(addrcmp(&l->sock->addr6, &ip, l->sock->af)))
				m = 0;
		} else {
			if (!(addrcmp((struct gwin6_addr *)&l->sock->addr, &ip, l->sock->af)))
				m = 0;
		}

		if (m)
			return l;
	}

	return NULL;
}

int listener_loop(ListenerLoopHandler handler) {
	struct Listener *l, *n;
	int c = 0;

	for (l = listeners; l != NULL; l = n) {
		n = l->next;
		if (((*handler) (l)) != 0) {
			c++;
		}
	}

	return c;
}

int listener_rebind(struct Listener *l) {
	if (!LstIsBound(l)) {
		if (socket_bind(l)) {
			LstSetBound(l);
			return 1;
		}
		alog(LOG_ERROR, "Bind error: %s", strerror(errno));
	}
	return 0;
}

int listener_delnoconf(struct Listener *l) {
	if (!LstIsAdded(l) && !l->clients)
		return listener_del(l);
	if (!LstIsAdded(l))
		LstSetClosed(l);
	return 0;
}

int listener_delnobound(struct Listener *l) {
	if (!LstIsBound(l))
		return listener_del(l);
	return 0;
}

int listener_clearadded(struct Listener *l) {
	LstClrAdded(l);
	return 1;
}

int listener_setremhost(struct Listener *l, char *raddr) {
	l->remaf = AF_INET;
	if (inet_pton(AF_INET, raddr, &l->remaddr) <= 0) {
		l->remaf = AF_INET6;
		if (inet_pton(AF_INET6, raddr, &l->remaddr6) <= 0) {
			return 0;
		}
	}
	return 1;
}

int listener_checkfd(struct Listener *l) {
	int fd = l->sock->fd;
	char *ip, *lip;
	char result[IPADDRMAXLEN];
	struct Client *cli;

	if (FD_ISSET(fd, &fds)) {
		if (IsIP6(l->sock))
			ip = (char *)inet_ntop(l->sock->af, &l->sock->addr6, result, IPADDRMAXLEN);
		else
			ip = (char *)inet_ntop(l->sock->af, &l->sock->addr, result, IPADDRMAXLEN);
		lip = strdup(ip);

		alog(LOG_DEBUG, "Incoming connection on [%s]:%d", lip, l->sock->port);
		cli = socket_accept(l);

		if (cli == NULL)
			return 0;

		if (IsIP6(cli->lsock))
			ip = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr6, result, IPADDRMAXLEN);
		else
			ip = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr, result, IPADDRMAXLEN);

		alog(LOG_NORM, "Accepted new client from [%s]:%d on [%s]:%d", ip, cli->lsock->port, lip, l->sock->port);

		if (!socket_connect(cli))
			return 0;

		if (l->remaf == AF_INET6)
			ip = (char *)inet_ntop(l->remaf, &l->remaddr6, result, IPADDRMAXLEN);
		else
			ip = (char *)inet_ntop(l->remaf, &l->remaddr, result, IPADDRMAXLEN);

		alog(LOG_DEBUG, "Connected to remote host [%s]:%d", ip, l->remport);

		free(lip);

		return 1;
	}

	return 0;
}

void listener_parseflags(struct Listener *l, char *flags) {
	int i = 0;

	for (i=0; i<strlen(flags); i++) {
		switch (flags[i]) {
			case 'S':
			case 's': {
				LstSetSSL(l);
				break;
			}
			case 'W':
			case 'w': {
				LstSetWebIRC(l);
				break;
			}
			case '6': {
				LstSetWebIRCv6(l);
				break;
			}
			case 'R':
			case 'r': {
				LstSetNoRDNS(l);
				break;
			}
			case 'H':
			case 'h': {
				LstSetNoSuffix(l);
				break;
			}
			case 'N':
			case 'n': {
				LstSetRDNSNoSuffix(l);
				break;
			}
			case 'L':
			case 'l': {
				LstSetLiteralIPv6(l);
				break;
			}
			case 'X':
			case 'x': {
				LstSetWebIRCExtra(l);
				break;
			}
		}
	}

	if (LstIsWebIRCExtra(l) && !LstIsWebIRC(l))
		LstClrWebIRCExtra(l);
	if (LstIsWebIRCv6(l) && !LstIsWebIRC(l))
		LstClrWebIRCv6(l);
}

char* listener_flags(struct Listener *l) {
	char *flags = strdup("--------");

	if (LstIsNoSuffix(l))
		flags[0] = 'H';
	if (LstIsLiteralIPv6(l))
		flags[1] = 'L';
	if (LstIsRDNSNoSuffix(l))
		flags[2] = 'N';
	if (LstIsNoRDNS(l))
		flags[3] = 'R';
	if (LstIsSSL(l))
		flags[4] = 'S';
	if (LstIsWebIRC(l))
		flags[5] = 'W';
	if (LstIsWebIRCv6(l))
		flags[6] = '6';
	if (LstIsWebIRCExtra(l))
		flags[7] = 'X';
	flags[8] = '\0';

	return flags;
}

