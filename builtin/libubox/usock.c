/**
 *   zstream - Minimalistic network stream library
 *   Copyright (C) 2011 Steven Barth <steven@midlink.org>
 *
 *   This library is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License,
 *   or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "usock.h"

#define USOCK_FAMILY(x) ((x) & 0xf0)
#define USOCK_SOCKTYPE(x) ((x) & 0xf)
#define USOCK_PROTOCOL(x) (((x) >> 8) & 0xff)


static void usock_set_flags(int sock, unsigned int type)
{
	if (!(type & USOCK_NOCLOEXEC))
		fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	if (type & USOCK_NONBLOCK)
		fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
}

static int usock_connect(const char *host, struct sockaddr *sa, int sa_len, int family, int type)
{
	int sock = socket(family, USOCK_SOCKTYPE(type), USOCK_PROTOCOL(type));
	if (sock < 0)
		return -1;

	usock_set_flags(sock, type);

	if (!connect(sock, sa, sa_len) || errno == EINPROGRESS)
		return sock;

	close(sock);
	return -1;
}

static int usock_inet(int type, const char *host, const char *service)
{
	struct addrinfo *result, *rp;
	struct addrinfo hints = {
		.ai_family = (USOCK_FAMILY(type) == USOCK_IPV6ONLY) ? AF_INET6 :
			(USOCK_FAMILY(type) == USOCK_IPV4ONLY) ? AF_INET : AF_UNSPEC,
		.ai_socktype = USOCK_SOCKTYPE(type),
		.ai_flags = AI_ADDRCONFIG
			| ((type & USOCK_SERVER) ? AI_PASSIVE : 0)
#ifndef __UCLIBC__
			| ((type & USOCK_LITERALPORT) ? 0 : AI_NUMERICSERV)
#endif
			| ((type & USOCK_NUMERICHOST) ? AI_NUMERICHOST : 0),
	};
	int sock = -1;

	errno = ENOENT;
	if (getaddrinfo((type & USOCK_BINDTODEV) ? NULL : host, service, &hints, &result))
		return -1;

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sock = usock_connect(host, rp->ai_addr, rp->ai_addrlen, rp->ai_family, type);
		if (sock >= 0)
			break;
	}

	freeaddrinfo(result);
	return sock;
}

int usock(int type, const char *host, const char *service) {
	int sock = usock_inet(type, host, service);

	if (sock < 0)
		return -1;

	return sock;
}
