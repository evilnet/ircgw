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

struct Listener* listener_add(char *addr, char *port) {
	struct Listener *new;
	struct addrinfo *ai;
	struct addrinfo aihints;
	int r = 0;

	memset(&aihints, 0, sizeof(struct addrinfo));

	aihints.ai_flags = 0;
	aihints.ai_family = AF_UNSPEC;
	aihints.ai_socktype = SOCK_STREAM;
	aihints.ai_protocol = IPPROTO_TCP;

	if ((r = getaddrinfo(addr, port, &aihints, &ai)) != 0) {
		alog(LOG_ERROR, "Error: getaddrinfo() error: %s", gai_strerror(r));
		return NULL;
	}

	new = listener_find((struct gw_sockaddr *)ai->ai_addr);

	if (new != NULL) {
		LstSetAdded(new);
		return new;
	}

	new = malloc(sizeof(struct Listener));
	memset(new, 0, sizeof(struct Listener));
	alog(LOG_DEBUG, "Lst: new(%s, %s)", addr, port);

	new->sock = socket_new();

	memcpy(&new->sock->sa, ai->ai_addr, ai->ai_addrlen);
	new->sock->salen = ai->ai_addrlen;
	freeaddrinfo(ai);

	if ((SockAF(new->sock) != AF_INET) && (SockAF(new->sock) != AF_INET6)) {
		alog(LOG_ERROR, "Error: Unknown address family for listener: %d", SockAF(new->sock));
		socket_del(new->sock);
		free(new);
		return NULL;
	}

	new->flags = 0;
	new->clients = 0;
	LstSetAdded(new);
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

struct Listener* listener_find(struct gw_sockaddr *sa) {
	struct Listener *l;
	struct gwin6_addr ip;
	int m = 0;
	int port = ntohs(sa->sa_port);

	if (sa->sa_family == AF_INET6)
		memcpy(&ip, &sa->sa_in6.sa_inaddr, sizeof(struct gwin6_addr));
	else
		memcpy(&ip, &sa->sa_in.sa_inaddr, sizeof(struct gwin_addr));

	for (l = listeners; l != NULL; l = l->next) {
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

int listener_setremhost(struct Listener *l, char *raddr, char *rport) {
	struct Listener *new;
	struct addrinfo *ai;
	struct addrinfo aihints;
	int r = 0;

	memset(&aihints, 0, sizeof(struct addrinfo));

	aihints.ai_flags = 0;
	aihints.ai_family = AF_UNSPEC;
	aihints.ai_socktype = SOCK_STREAM;
	aihints.ai_protocol = IPPROTO_TCP;

	if ((r = getaddrinfo(raddr, rport, &aihints, &ai)) != 0) {
		alog(LOG_ERROR, "Error: getaddrinfo() error: %s", gai_strerror(r));
		return 0;
	}

	memcpy(&l->remsa, ai->ai_addr, ai->ai_addrlen);
	l->remsalen = ai->ai_addrlen;
	freeaddrinfo(ai);

	if ((l->remsa.sa_family != AF_INET) && (l->remsa.sa_family != AF_INET6)) {
		alog(LOG_ERROR, "Error: Unknown address family for remote: %d", SockAF(new->sock));
		return 0;
	}

	return 1;
}

int listener_checkfd(struct Listener *l) {
	int fd = l->sock->fd;
	char ip[IPADDRMAXLEN], sip[IPADDRMAXLEN], lip[IPADDRMAXLEN];
	char port[PORTMAXLEN], sport[PORTMAXLEN], lport[PORTMAXLEN];
	struct Client *cli;
	struct gw_sockaddr sa;
	int size = 0;

	memset(&ip, 0, IPADDRMAXLEN);
	memset(&sip, 0, IPADDRMAXLEN);
	memset(&lip, 0, IPADDRMAXLEN);
	memset(&port, 0, PORTMAXLEN);
	memset(&sport, 0, PORTMAXLEN);
	memset(&lport, 0, PORTMAXLEN);

	if (FD_ISSET(fd, &fds)) {
		cli = socket_accept(l);

		if (cli == NULL)
			return 0;

		getnameinfo((struct sockaddr *)&l->sock->sa, l->sock->salen, (char *)&lip, IPADDRMAXLEN,
			(char *)&lport, PORTMAXLEN, NI_NUMERICHOST | NI_NUMERICSERV);
		
		size = sizeof(struct gw_sockaddr);
		getsockname(cli->lsock->fd, (struct sockaddr *)&sa, (socklen_t*)&size);

		getnameinfo((struct sockaddr *)&sa, size, (char *)&sip, IPADDRMAXLEN,
			(char *)&sport, PORTMAXLEN, NI_NUMERICHOST | NI_NUMERICSERV);

		getnameinfo((struct sockaddr *)&cli->lsock->sa, cli->lsock->salen,
			(char *)&ip, IPADDRMAXLEN, (char *)&port, PORTMAXLEN, NI_NUMERICHOST | NI_NUMERICSERV);

		alog(LOG_NORM, "Accepted new client from [%s]:%s to [%s]:%s on [%s]:%s", ip, port, sip, sport, lip, lport);

		if (!socket_connect(cli))
			return 0;

		getnameinfo((struct sockaddr *)&l->remsa, l->remsalen, (char *)&ip, IPADDRMAXLEN,
			(char *)&port, PORTMAXLEN, NI_NUMERICHOST | NI_NUMERICSERV);

		alog(LOG_DEBUG, "Connected to remote host [%s]:%s", ip, port);

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

	flags[0] = LstIsNoSuffix(l) ? 'H' : '-';
	flags[1] = LstIsLiteralIPv6(l) ? 'L' : '-';
	flags[2] = LstIsRDNSNoSuffix(l) ? 'N' : '-';
	flags[3] = LstIsNoRDNS(l) ? 'R' : '-';
	flags[4] = LstIsSSL(l) ? 'S' : '-';
	flags[5] = LstIsWebIRC(l) ? 'W' : '-';
	flags[6] = LstIsWebIRCv6(l) ? '6' : '-';
	flags[7] = LstIsWebIRCExtra(l) ? 'X' : '-';
	flags[8] = '\0';

	return (char *)&flags;
}

