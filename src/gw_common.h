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

#define SockAF(s)		(s->sa.sa_family)
#define SockPort(s)		(ntohs(s->sa.sa_port))

#define IsIP6(o)		((SockAF(o) == AF_INET6) ? 1 : 0)
#define IsIP6to4(o)		((o->addr6.addr.addr16[0] == htons(0x2002)) ? 1 : 0)
#define IsIP6Teredo(o)		((o->addr6.addr.addr16[0] == htons(0x2001)) && (o->addr6.addr.addr16[1] == 0) ? 1 : 0)

struct gwin6_addr {
	union {
		uint8_t		addr8[16];
		uint16_t	addr16[8];
		uint32_t	addr32[4];
	} addr;
};

struct gwin_addr {
	union {
		uint8_t		addr8[4];
		uint16_t	addr16[2];
		uint32_t	addr32[1];
	} addr;
};

struct gw_sockaddr {
	uint8_t sa_len;
	uint8_t sa_family;
	uint16_t sa_port;
	union {
		struct {
			struct gwin_addr sa_inaddr;
			uint8_t sa_pack[20];
		} sa_in;
		struct {
			uint32_t sa_flowinfo;
			struct gwin6_addr sa_inaddr;
			uint32_t sa_scope_id;
		} sa_in6;
	};
};

struct Socket {
	struct Socket *next;
	struct Socket *prev;
	struct gw_sockaddr sa;		/* Socket address of this socket */
	struct gwin6_addr addr6;	/* IPv6 address */
	struct gwin_addr addr;		/* IPv4 address */
	socklen_t salen;		/* Size of socket address struct */
	int fd;				/* File descriptor */
	SSL *ssl;			/* SSL connection */
	char sslfp[65];			/* SSL fingerprint */
};

struct Listener {
	struct Listener *next;
	struct Listener *prev;
	struct Socket *sock;		/* Socket associated with Listener */
	struct gw_sockaddr remsa;	/* Remote socket address (to connect to) */
	socklen_t remsalen;		/* Size of remote socket address struct */
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

