/*
 * IRCGW - Internet Relay Chat Gateway, src/gw_webirc.c
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
#include "gw_webirc.h"

char* expandaddr6(struct gwin6_addr *a) {
	char *ret = malloc(IPEXPMAXLEN);

	sprintf(ret, "%08x%08x%08x%08x", htonl(a->addr.addr32[0]),
		htonl(a->addr.addr32[1]), htonl(a->addr.addr32[2]),
		htonl(a->addr.addr32[3]));

	return ret;
}

char* expandaddr6colon(struct gwin6_addr *a) {
	char *ret = malloc(IPEXPMAXLEN);

	sprintf(ret, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		htons(a->addr.addr16[0]), htons(a->addr.addr16[1]),
		htons(a->addr.addr16[2]), htons(a->addr.addr16[3]),
		htons(a->addr.addr16[4]), htons(a->addr.addr16[5]),
		htons(a->addr.addr16[6]), htons(a->addr.addr16[7]));

	return ret;
}

char* get_rdns6(struct gwin6_addr ipaddr) {
	struct hostent *her;
	struct hostent *hef;
	int i = 0;
	int valid = 0;

	her = gethostbyaddr((const void *)&ipaddr, sizeof ipaddr, AF_INET6);
	
	if (her) {
		hef = gethostbyname2(her->h_name, AF_INET6);
		if (hef) {
			while ((hef->h_addr_list[i] != NULL) && !valid) {
				if (addrcmp((struct gwin6_addr *)&ipaddr, (struct gwin6_addr *)hef->h_addr_list[i], AF_INET6))
					valid = 1;
				i++;
			}
		}
	}
	
	if (valid && her)
		return her->h_name;
	else
		return NULL;
}

char* get_rdns(struct gwin_addr ipaddr) {
	struct hostent *her;
	struct hostent *hef;
	int i = 0;
	int valid = 0;
	
	her = gethostbyaddr((const void *)&ipaddr, sizeof ipaddr, AF_INET);
	
	if (her) {
		hef = gethostbyname2(her->h_name, AF_INET);
		if (hef) {
			while ((hef->h_addr_list[i] != NULL) && !valid) {
				if (addrcmp((struct gwin6_addr *)&ipaddr, (struct gwin6_addr *)hef->h_addr_list[i], AF_INET))
					valid = 1;
				i++;
			}
		}
	}
	
	if (valid && her)
		return her->h_name;
	else
		return NULL;
}

char* getwebircmsg(struct Client *cli) {
	char *msg, *ip, *ipexp;
	char *ip6, *host, *hostpart = NULL;
	char result[IPADDRMAXLEN];
	int i = 0, hostfree = 0, hpfree = 0, rdnsdone = 0;
	unsigned char hash1[16], hash2[16], hash3[16];
	MD5_CTX ctx1, ctx2, ctx3;

	assert(cli != NULL);
	assert(cli->listener != NULL);
	
	if (!cli->listener->wircpass || !LstIsWebIRC(cli->listener))
		return NULL;

	if (IsIP6(cli->lsock)) {
		ip6 = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr6, result, IPADDRMAXLEN);
		if (!LstIsNoRDNS(cli->listener))
			hostpart = get_rdns6(cli->lsock->addr6);
		if (hostpart != NULL)
			rdnsdone = 1;
		if (LstIsWebIRCv6(cli->listener)) {
			ip = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr6, result, IPADDRMAXLEN);
			if (hostpart == NULL)
				hostpart = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr6, result, IPADDRMAXLEN);

			if (cli->listener->wircsuff && !LstIsNoSuffix(cli->listener) && !(rdnsdone && LstIsRDNSNoSuffix(cli->listener))) {
				hostfree = 1;
				host = malloc(HOSTMAXLEN);
				sprintf(host, "%s.%s", hostpart, cli->listener->wircsuff);
			} else
				host = hostpart;
		} else {
			MD5_Init(&ctx1);
			for (i=0; i<8; i++) {
				MD5_Update(&ctx1, (unsigned const char*)&cli->lsock->addr6.addr.addr8[i], 1);
			}
			MD5_Final(hash1, &ctx1);

			MD5_Init(&ctx2);
			for (i=8; i<12; i++) {
				MD5_Update(&ctx2, (unsigned const char*)&cli->lsock->addr6.addr.addr8[i], 1);
			}
			MD5_Final(hash2, &ctx2);

			MD5_Init(&ctx3);
			for (i=12; i<16; i++) {
				MD5_Update(&ctx3, (unsigned const char*)&cli->lsock->addr6.addr.addr8[i], 1);
			}
			MD5_Final(hash3, &ctx3);

			ip = malloc(15);
			sprintf(ip, "0.%d.%d.%d", hash1[3], hash2[7], hash3[11]);

			if (hostpart == NULL) {
				hpfree = 1;
				if (LstIsLiteralIPv6(cli->listener))
					hostpart = expandaddr6colon(&cli->lsock->addr6);
				else {
					ipexp = expandaddr6(&cli->lsock->addr6);
					hostpart = gw_strrev(ipexp);
					free(ipexp);
				}
			}

			if (cli->listener->wircsuff && !LstIsNoSuffix(cli->listener) && !(rdnsdone && LstIsRDNSNoSuffix(cli->listener))) {
				hostfree = 1;
				host = malloc(HOSTMAXLEN);
				sprintf(host, "%s.%s", hostpart, cli->listener->wircsuff);
			} else
				host = hostpart;
		}
	} else {
		ip6 = NULL;
		ip = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr, result, IPADDRMAXLEN);
		if (!LstIsNoRDNS(cli->listener))
			hostpart = get_rdns(cli->lsock->addr);
		if (hostpart == NULL)
			hostpart = (char *)inet_ntop(cli->lsock->af, &cli->lsock->addr, result, IPADDRMAXLEN);
		else
			rdnsdone = 1;

		if (cli->listener->wircsuff && !LstIsNoSuffix(cli->listener) && !(rdnsdone && LstIsRDNSNoSuffix(cli->listener))) {
			hostfree = 1;
			host = malloc(HOSTMAXLEN);
			sprintf(host, "%s.%s", hostpart, cli->listener->wircsuff);
		} else
			host = hostpart;
	}

	msg = malloc(IRCMSGMAXLEN);
	if (ip6 != NULL)
		sprintf(msg, MSG_WEBIRC_EXT, cli->listener->wircpass, host, ip, ip6);
	else
		sprintf(msg, MSG_WEBIRC, cli->listener->wircpass, host, ip);

	if (hostfree)
		free(host);
	if (hpfree)
		free(hostpart);
	if (IsIP6(cli->lsock) && !LstIsWebIRCv6(cli->listener))
		free(ip);

	return msg;
}

