/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_webirc.h
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
#ifndef GW_WEBIRC_H
#define GW_WEBIRC_H

#include "gw_common.h"
#include "gw_client.h"

#define MSG_WEBIRC	"WEBIRC %s ircgw %s %s\r\n"
#define MSG_WEBIRC_EXT	"WEBIRC %s ircgw %s %s :%s\r\n"

char* expandaddr6(struct gwin6_addr *a);
char* expandaddr6colon(struct gwin6_addr *a);
char* get_rdns6(struct gwin6_addr ipaddr);
char* get_rdns(struct gwin_addr ipaddr);
char* getwebircmsg(struct Client *cli);

#endif
