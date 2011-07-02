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
 * $Id$
 */
#include "gw_sockets.h"

struct Socket* socket_new() {
	struct Socket *new;

	new = malloc(sizeof(struct Socket));
	memset(new, 0, sizeof(struct Socket));
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
	int optval = 1;
	int bindRes = 0;

	if ((l->sock->fd = socket(SockAF(l->sock), SOCK_STREAM, 0)) == -1)
		return 0;

	if (LstIsBound(l))
		return 0;

	setsockopt(l->sock->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (l->sock->sa.sa_family == AF_INET6)
		setsockopt(l->sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));

	bindRes = bind(l->sock->fd, (struct sockaddr *)&l->sock->sa, l->sock->salen);

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
	int res = 0;

	if ((c->rsock->fd = socket(c->listener->remsa.sa_family, SOCK_STREAM, 0)) < 0) {
		client_del(c);
		return 0;
	}

	res = connect(c->rsock->fd, (struct sockaddr*)&c->listener->remsa, c->listener->remsalen);

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
	char *h;

	assert(l != NULL);

	cli = client_new(l);

	cli->lsock->salen = sizeof(struct gw_sockaddr);
	cli->lsock->fd = accept(l->sock->fd, (struct sockaddr*)&cli->lsock->sa, (socklen_t*)&cli->lsock->salen);

	if (LstIsClosed(l) || (cli->lsock->fd < 0)) {
		client_del(cli);
		return NULL;
	}

	if (LstIsSSL(l)) {
		cli->lsock->ssl = gw_ssl_accept(cli->lsock->fd);
		if (cli->lsock->ssl) {
			if ((h = gw_ssl_get_hash(cli->lsock->ssl))) {
				alog(LOG_DEBUG, "Client certificate SHA256: %s", gw_strhex(h, 32));
				strncpy((char *)&cli->lsock->sslfp, gw_strhex(h, 32), 65);
			}
		}
	} else
		cli->lsock->ssl = NULL;

	alog(LOG_DEBUG, "New FD: %d", cli->lsock->fd);

	return cli;
}

char* socket_read(struct Socket *s) {
	static char buf[4096];
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

	return (buf);
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

