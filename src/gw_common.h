/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_common.h
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
#ifndef GW_COMMON_H
#define GW_COMMON_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#define DEFCONF	"ircgw.conf"
#define DEFCERT	"ircgw.cer"
#define DEFKEY	"ircgw.key"
#define DEFPID	"ircgw.pid"

#define IPADDRMAXLEN	INET6_ADDRSTRLEN
#define IPEXPMAXLEN	33
#define HOSTMAXLEN	256
#define IRCMSGMAXLEN	512

#define BUFSIZE		1024

#define	HasFlag(o, flag)	((o->flags & flag) ? 1 : 0)
#define SetFlag(o, flag)	o->flags |= flag
#define ClrFlag(o, flag)	o->flags &= ~flag

#define SockAF(s)		s->af
#define SockPort(s)		s->port
#define SockIn(s)		s->addr
#define SockIn6(s)		s->addr6

#define IsIP6(s)		((SockAF(s) == AF_INET6) ? 1 : 0)
#define IsIP6to4(s)		(IsIP6(s) && (SockIn6(s).addr16[0] == htons(0x2002)) ? 1 : 0)
#define IsIP6Teredo(s)		(IsIP6(s) && (SockIn6(s).addr16[0] == htons(0x2001)) && (SockIn6(s).addr16[1] == 0) ? 1 : 0)

struct gwin6_addr {
	union {
		uint8_t		addr8[16];
		uint16_t	addr16[8];
		uint32_t	addr32[4];
	};
};

struct gwin_addr {
	union {
		uint8_t		addr8[4];
		uint16_t	addr16[2];
		uint32_t	addr32[1];
	};
};

struct Socket {
	struct Socket *next;
	struct Socket *prev;
	struct gwin6_addr addr6;	/* IPv6 address */
	struct gwin_addr addr;		/* IPv4 address */
	int port;			/* Local Port */
	int af;				/* AF_INET or AF_INET6 */
	int fd;				/* File descriptor */
	SSL *ssl;			/* SSL connection */
	char sslfp[65];			/* SSL fingerprint */
};

struct Listener {
	struct Listener *next;
	struct Listener *prev;
	struct Socket *sock;		/* Socket associated with Listener */
	struct gwin6_addr remaddr6;	/* Remote IPv6 address */
	struct gwin_addr remaddr;	/* Remote IPv4 address */
	int remport;			/* Remote Port */
	int remaf;			/* Remote: AF_INET or AF_INET6 */
	int flags;			/* Listener flags (Added, Bound, Gagged) */
	int clients;			/* Current client count */
	char wircpass[255];		/* WEBIRC Password */
	char wircsuff[255];		/* WEBIRC Host Suffix */
};

struct Client {
	struct Client *next;
	struct Client *prev;
	struct Socket *lsock;		/* Local (Inbound) Socket */
	struct Socket *rsock;		/* Remote (Outbound) Socket */
	struct Listener *listener;	/* Listener Connected To */
	int flags;
};

int addrcmp(struct gwin6_addr *a, struct gwin6_addr *b, int af);

#include "gw_log.h"
#include "gw_config.h"

#endif

