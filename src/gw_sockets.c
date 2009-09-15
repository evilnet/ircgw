/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_sockets.c
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
#include "gw_sockets.h"

struct Socket* socket_new() {
	struct Socket *new;

	new = malloc(sizeof(struct Socket));
	alog(LOG_DEBUG, "Sck: new()");

	new->fd = -1;
	new->ssl = NULL;

	new->prev = NULL;
	if (sockets != NULL)
		sockets->prev = new;
	new->next = sockets;
	sockets = new;

	return new;
}

int socket_del(struct Socket *s) {
	assert(s != NULL);

	if (s->next != NULL)
		s->next->prev = s->prev;
	if (s->prev == NULL)
		sockets = s->next;
	else
		s->prev->next = s->next;

	alog(LOG_DEBUG, "Sck free()");
	free(s);
	return 1;
}

struct Socket* socket_find(int fd) {
	struct Socket *s;

	for (s=sockets; (s!=NULL); s=s->next) {
		if (s->fd == fd)
			return s;
	}

	return NULL;
}

int socket_loop(SocketLoopHandler handler) {
	struct Socket *s;
	struct Socket *n;
	int c = 0;

	for (s=sockets; (s!=NULL); s=n) {
		n = s->next;
		if (((*handler) (s)) != 0)
			c++;
	}

	return c;
}

int socket_count(struct Socket *s) {
	assert(s != NULL);
	if (s->fd == -1)
		return 0;
	return 1;
}

int socket_fdset(struct Socket *s) {
	if (s->fd == -1)
		return 0;

	if (s->fd > highestfd)
		highestfd = s->fd;
	FD_SET(s->fd, &fds);
	return 1;
}

int sockets_count() {
	return socket_loop(socket_count);
}

void sockets_fdset() {
	FD_ZERO(&fds);
	highestfd = 0;

	socket_loop(socket_fdset);
}

int socket_bind(struct Listener *l) {
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa;
	int optval = 1;
	int bindRes = 0;

	if ((l->sock->fd = socket(l->sock->af, SOCK_STREAM, 0)) == -1)
		return 0;

	if (LstIsBound(l))
		return 0;

	setsockopt(l->sock->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (IsIP6(l->sock)) {
		memset(&sa6, 0, sizeof(sa6));
		sa6.sin6_family = l->sock->af;
		sa6.sin6_port = htons(l->sock->port);
		memcpy(&(sa6.sin6_addr), &l->sock->addr6, sizeof(l->sock->addr6));
	} else {
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = l->sock->af;
		sa.sin_port = htons(l->sock->port);
		memcpy(&(sa.sin_addr), &l->sock->addr, sizeof(l->sock->addr));
		bzero(&(sa.sin_zero), 8);
	}

	if (IsIP6(l->sock))
		bindRes = bind(l->sock->fd, (struct sockaddr *)&sa6, sizeof(struct sockaddr_in6));
	else
		bindRes = bind(l->sock->fd, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));

	if(bindRes != 0) {
		close(l->sock->fd);
		return 0;
	}
	
	if (listen(l->sock->fd, 10) != 0) {
		shutdown(l->sock->fd, SHUT_RDWR);
		close(l->sock->fd);
		return 0;
	}

	return 1;
}

int socket_connect(struct Client *c) {
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa;
	int res = 0;

	if ((c->rsock->fd = socket(c->listener->remaf, SOCK_STREAM, 0)) < 0) {
		client_del(c);
		return 0;
	}

	if (c->listener->remaf == AF_INET6) {
		memset(&sa6, 0, sizeof(struct sockaddr_in6));
		memcpy(&(sa6.sin6_addr), &c->listener->remaddr6, sizeof(c->listener->remaddr6));
		sa6.sin6_family = c->listener->remaf;
		sa6.sin6_port = htons(c->listener->remport);
		res = connect(c->rsock->fd, (struct sockaddr*)&sa6, sizeof(sa6));
	} else {
		memset(&sa, 0, sizeof(struct sockaddr_in));
		memcpy(&(sa.sin_addr), &c->listener->remaddr, sizeof(c->listener->remaddr));
		sa.sin_family = c->listener->remaf;
		sa.sin_port = htons(c->listener->remport);
		res = connect(c->rsock->fd, (struct sockaddr*)&sa, sizeof(sa));
	}

	if (res < 0) {
		client_del(c);
		return 0;
	}

	if (LstIsSSL(c->listener))
		c->rsock->ssl = gw_ssl_connect(c->rsock->fd);
	else
		c->rsock->ssl = NULL;

	return 1;
}

int socket_close_listener(struct Listener *l) {
	assert(l != NULL);
	assert(l->sock != NULL);

	shutdown(l->sock->fd, SHUT_RDWR);
	close(l->sock->fd);

	socket_del(l->sock);

	return 1;
}

int socket_close(struct Socket *s) {
	assert(s != NULL);

	if (s->ssl != NULL) {
		alog(LOG_DEBUG, "Ssl: SSL_free()");
		SSL_free(s->ssl);
	}

	shutdown(s->fd, SHUT_RDWR);
	close(s->fd);

	socket_del(s);

	return 1;
}

struct Client* socket_accept(struct Listener *l) {
	struct Client *cli;
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa;
	int size = 0;

	assert(l != NULL);

	cli = client_new(l);

	if (IsIP6(l->sock)) {
		size = sizeof(struct sockaddr_in6);
		cli->lsock->fd = accept(l->sock->fd, (struct sockaddr*)&sa6, (socklen_t*)&size);
		memcpy(&(cli->lsock->addr6), &sa6.sin6_addr, sizeof(struct gwin6_addr));
		cli->lsock->port = ntohs(sa6.sin6_port);
		cli->lsock->af = sa6.sin6_family;
	} else {
		size = sizeof(struct sockaddr_in);
		cli->lsock->fd = accept(l->sock->fd, (struct sockaddr*)&sa, (socklen_t*)&size);
		memcpy(&(cli->lsock->addr), &sa.sin_addr, sizeof(struct gwin_addr));
		cli->lsock->port = ntohs(sa.sin_port);
		cli->lsock->af = sa.sin_family;
	}

	if (LstIsClosed(l) || (cli->lsock->fd < 0)) {
		client_del(cli);
		return NULL;
	}

	if (LstIsSSL(l))
		cli->lsock->ssl = gw_ssl_accept(cli->lsock->fd);
	else
		cli->lsock->ssl = NULL;

	alog(LOG_DEBUG, "New FD: %d (%d)", cli->lsock->fd, (int)sizeof(cli));

	return cli;
}

char* socket_read(struct Socket *s) {
	char buf[4096];
	int lenread;

	assert(s != NULL);

	if(s->fd == -1)
		return NULL;

	if (s->ssl != NULL)
		lenread = SSL_read(s->ssl, &buf, 4096);
	else
		lenread = read(s->fd, &buf, 4096);

	if (lenread == -1)
		buf[0] = '\0';
	buf[lenread] = '\0';

	return strdup(buf);
}

int socket_write(struct Socket *s, char *in) {
	int lenwrite = 0;

	assert(s != NULL);
	if (s->fd == -1)
		return 0;

	if (s->ssl != NULL)
		lenwrite = SSL_write(s->ssl, in, strlen(in));
	else
		lenwrite = write(s->fd, in, strlen(in));

	return lenwrite;
}

int sockets_check() {
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1000;

	sockets_fdset();

	select(highestfd+1, &fds, NULL, NULL, &tv);

	listener_loop(listener_checkfd);

	client_loop(client_checkfd);

	return sockets_count();
}

