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
	memset(new, 0, sizeof(struct Listener));
	alog(LOG_DEBUG, "Lst: new()");

	new->sock = socket_new();

	SockAF(new->sock) = AF_INET;
	if (inet_pton(AF_INET, addr, &SockIn(new->sock)) <= 0) {
		SockAF(new->sock) = AF_INET6;
		if (inet_pton(AF_INET6, addr, &SockIn6(new->sock)) <= 0) {
			socket_del(new->sock);
			free(new);
			return NULL;
		}
	}

	new->flags = 0;
	new->clients = 0;
	LstSetAdded(new);
	SockPort(new->sock) = port;
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
		if (inet_pton(SockAF(l->sock), addr, &ip) <= 0)
			continue;

		if (port == SockPort(l->sock))
			m = 1;
		if (IsIP6(l->sock)) {
			if (!(addrcmp(&SockIn6(l->sock), &ip, SockAF(l->sock))))
				m = 0;
		} else {
			if (!(addrcmp((struct gwin6_addr *)&SockIn(l->sock), &ip, SockAF(l->sock))))
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
		listener_del(l);
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
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa;
	int size = 0;

	if (FD_ISSET(fd, &fds)) {
		cli = socket_accept(l);

		if (cli == NULL)
			return 0;

		if (IsIP6(l->sock)) {
			size = sizeof(struct sockaddr_in6);
			getsockname(cli->lsock->fd, (struct sockaddr *)&sa6, (socklen_t*)&size);
			ip = (char *)inet_ntop(SockAF(l->sock), &sa6.sin6_addr, result, IPADDRMAXLEN);
		} else {
			size = sizeof(struct sockaddr_in);
			getsockname(cli->lsock->fd, (struct sockaddr *)&sa, (socklen_t*)&size);
			ip = (char *)inet_ntop(SockAF(l->sock), &sa.sin_addr, result, IPADDRMAXLEN);
		}
		lip = strdup(ip);

		alog(LOG_DEBUG, "Incoming connection on [%s]:%d", lip, SockPort(l->sock));

		if (IsIP6(cli->lsock))
			ip = (char *)inet_ntop(SockAF(cli->lsock), &SockIn6(cli->lsock), result, IPADDRMAXLEN);
		else
			ip = (char *)inet_ntop(SockAF(cli->lsock), &SockIn(cli->lsock), result, IPADDRMAXLEN);

		alog(LOG_NORM, "Accepted new client from [%s]:%d on [%s]:%d", ip, SockPort(cli->lsock), lip, SockPort(l->sock));

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
	static char flags[9];
	char *f = (char *)&flags;

	memset(&flags, 0, 9);

	if (LstIsNoSuffix(l))
		*f++ = 'H';
	if (LstIsLiteralIPv6(l))
		*f++ = 'L';
	if (LstIsRDNSNoSuffix(l))
		*f++ = 'N';
	if (LstIsNoRDNS(l))
		*f++ = 'R';
	if (LstIsSSL(l))
		*f++ = 'S';
	if (LstIsWebIRC(l))
		*f++ = 'W';
	if (LstIsWebIRCv6(l))
		*f++ = '6';
	if (LstIsWebIRCExtra(l))
		*f++ = 'X';
	*f = '\0';

	return (char *)&flags;
}

