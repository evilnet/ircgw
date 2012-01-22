/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_listener.h
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
#ifndef GW_LISTENER_H
#define GW_LISTENER_H

#include "gw_common.h"
#include "gw_sockets.h"
#include "gw_webirc.h"

#define	LFLAG_ADDED		0x00000001
#define LFLAG_BOUND		0x00000002
#define LFLAG_CLOSED		0x00000004
#define LFLAG_SSL		0x00000010
#define LFLAG_WEBIRC		0x00000020
#define LFLAG_WEBIRCV6		0x00000040
#define	LFLAG_NORDNS		0x00000080
#define LFLAG_NOSUFFIX		0x00000100
#define LFLAG_RNSNOSUFFIX	0x00000200
#define LFLAG_LITERALIPV6	0x00000400
#define LFLAG_WEBIRCEXTRA       0x00000800

#define	LstIsAdded(l)		HasFlag(l, LFLAG_ADDED)
#define LstIsBound(l)   	HasFlag(l, LFLAG_BOUND)
#define LstIsClosed(l)		HasFlag(l, LFLAG_CLOSED)
#define TLstIsSSL(l)		HasFlag(l, LFLAG_SSL)
#define LstIsSSL(l)		((TLstIsSSL(l) && sslenabled) ? 1 : 0)
#define LstIsWebIRC(l)		HasFlag(l, LFLAG_WEBIRC)
#define LstIsWebIRCv6(l)	HasFlag(l, LFLAG_WEBIRCV6)
#define LstIsNoRDNS(l)		HasFlag(l, LFLAG_NORDNS)
#define LstIsNoSuffix(l)	HasFlag(l, LFLAG_NOSUFFIX)
#define LstIsRDNSNoSuffix(l)	HasFlag(l, LFLAG_RNSNOSUFFIX)
#define LstIsLiteralIPv6(l)	HasFlag(l, LFLAG_LITERALIPV6)
#define LstIsWebIRCExtra(l)	HasFlag(l, LFLAG_WEBIRCEXTRA)

#define LstSetAdded(l)		SetFlag(l, LFLAG_ADDED)
#define LstSetBound(l)  	SetFlag(l, LFLAG_BOUND)
#define LstSetClosed(l)		SetFlag(l, LFLAG_CLOSED)
#define LstSetSSL(l)		SetFlag(l, LFLAG_SSL)
#define LstSetWebIRC(l)		SetFlag(l, LFLAG_WEBIRC)
#define LstSetWebIRCv6(l)	SetFlag(l, LFLAG_WEBIRCV6)
#define LstSetNoRDNS(l)		SetFlag(l, LFLAG_NORDNS)
#define LstSetNoSuffix(l)	SetFlag(l, LFLAG_NOSUFFIX)
#define LstSetRDNSNoSuffix(l)	SetFlag(l, LFLAG_RNSNOSUFFIX)
#define LstSetLiteralIPv6(l)	SetFlag(l, LFLAG_LITERALIPV6)
#define LstSetWebIRCExtra(l)	SetFlag(l, LFLAG_WEBIRCEXTRA)

#define LstClrAdded(l)		ClrFlag(l, LFLAG_ADDED)
#define LstClrBound(l)  	ClrFlag(l, LFLAG_BOUND)
#define LstClrClosed(l)		ClrFlag(l, LFLAG_CLOSED)
#define LstClrSSL(l)		ClrFlag(l, LFLAG_SSL)
#define LstClrWebIRC(l)		ClrFlag(l, LFLAG_WEBIRC)
#define LstClrWebIRCv6(l)	ClrFlag(l, LFLAG_WEBIRCV6)
#define LstClrNoRDNS(l)		ClrFlag(l, LFLAG_NORDNS)
#define LstClrNoSuffix(l)	ClrFlag(l, LFLAG_NOSUFFIX)
#define LstClrRDNSNoSuffix(l)	ClrFlag(l, LFLAG_RNSNOSUFFIX)
#define LstClrLiteralIPv6(l)	ClrFlag(l, LFLAG_LITERALIPV6)
#define LstClrWebIRCExtra(l)	ClrFlag(l, LFLAG_WEBIRCEXTRA)

struct Listener *listeners;

typedef int (*ListenerLoopHandler)(struct Listener* listener);

struct Listener* listener_add (char *addr, int port);
int listener_del(struct Listener* l);
struct Listener* listener_find (char *addr, int port);
int listener_loop (ListenerLoopHandler handler);
int listener_rebind(struct Listener *l);
int listener_delnoconf(struct Listener *l);
int listener_delnobound(struct Listener *l);
int listener_clearadded(struct Listener *l);
int listener_checkfd(struct Listener *l);
int listener_setremhost(struct Listener *l, char *raddr);
void listener_parseflags(struct Listener *l, char *flags);
char* listener_flags(struct Listener *l);

#endif

