/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_client.c
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
#include "gw_client.h"

struct Client* client_new(struct Listener *l) {
	struct Client *new;

	new = malloc(sizeof(struct Client));
	alog(LOG_DEBUG, "Cli: new()");

	new->lsock = socket_new();
	new->rsock = socket_new();
	new->listener = l;

	new->flags = 0;

	new->prev = NULL;
	if (clients != NULL)
		clients->prev = new;
	new->next = clients;
	clients = new;

	l->clients++;

	return new;
}

int client_del(struct Client *c) {
	assert(c != NULL);

	socket_close(c->lsock);
	socket_close(c->rsock);

	if (c->next != NULL)
		c->next->prev = c->prev;
	if (c->prev == NULL)
		clients = c->next;
	else
		c->prev->next = c->next;

	c->listener->clients--;

	if (!LstIsAdded(c->listener) && !c->listener->clients)
		listener_del(c->listener);

	alog(LOG_DEBUG, "Cli free()");
	free(c);
	return 1;
}

int client_loop(ClientLoopHandler handler) {
	struct Client *n;
	struct Client *c;
	int count = 0;

	for (c=clients; c!=NULL; c=n) {
		n = c->next;
		if (((*handler) (c)) != 0)
			count++;
	}

	return count;
}

int client_count(struct Client *c) {
	return 1;
}

int client_checkfd(struct Client *c) {
        int fdl = c->lsock->fd;
	int fdr = c->rsock->fd;
	char *buf;
	char *wirc, *wircex;

	if (FD_ISSET(fdl, &fds)) {
		buf = socket_read(c->lsock);
		if (buf[0] == 0) {
			alog(LOG_DEBUG, "FD %d closed",  c->lsock->fd);
			client_del(c);
			alog(LOG_DEBUG, "Sockets: %d", sockets_count());
			return 0;
		} else {
			if (!CliIsWebIRCSent(c)) {
				CliSetWebIRCSent(c);
				wirc = getwebircmsg(c);
				if (wirc != NULL) {
					socket_write(c->rsock, wirc);
					free(wirc);
				}
				if (LstIsWebIRCExtra(c->listener) && c->lsock->sslfp) {
					wircex = getwebircextramsg(c, "sslfp", c->lsock->sslfp);
					if (wircex != NULL) {
						socket_write(c->rsock, wircex);
						free(wircex);
					}
				}
			}
			socket_write(c->rsock, buf);
		}
	}

	if (FD_ISSET(fdr, &fds)) {
		buf = socket_read(c->rsock);
		if (buf[0] == 0) {
			alog(LOG_DEBUG, "FD %d closed",  c->rsock->fd);
			client_del(c);
			alog(LOG_DEBUG, "Sockets: %d", sockets_count());
			return 0;
		} else {
			socket_write(c->lsock, buf);
		}
	}

	return 1;
}

