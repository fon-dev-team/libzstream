/*
 * host.c - Parsing host input to get its components.
 * Copyrigth (C) 2016 Alejandro Martin <alejandro.martin@fon.com>
 * Copyright (C) 2011 Steven Barth <steven@midlink.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License,
 * or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 */

#include <string.h>
#include <stdlib.h>
#include <data.h>
#include "host.h"

enum proto {
	NO_PROTO,
	HTTPS,
	HTTP
};

/*
 * Splits the url into its components
 * scheme:[//[user:password@]host[:port]][/]path[?query][#fragment]
 *
 * scheme must be http or https (http is set otherwise)
 * if not port available then http port is set to 80 and https port to 443
 *
 * This function
 */
void host_url_parse(struct host *host, const char *src)
{
	const char *delim;
	size_t dlength = strlen("://");
	size_t plen = 0;

	host->url = strdup(src);
	delim = strstr(src, "://");
	
	/*
	 * Supported protocols HTTP or HTTPS. Setting HTTP by default
	 */
	if (delim && !strncmp("https", src, strlen("https"))) {
		host->proto = HTTPS;
	} else {
		host->proto = HTTP;
	}

	if (delim) {
		plen = delim - src + dlength;
	}
	
	const char *s_url = src + plen;
	const char *ptr;
	const char *end;
	
	ptr = strchr(s_url, '/');
	if (ptr) {
		host->path = strdup(ptr);
	} else {
		host->path = strdup("/");
		/* If not path the ptr points the end of the url */
		ptr = s_url + strlen(s_url);
	}

	/* check for auth values */
	end = ptr;
	ptr = strchr(s_url, '@');
	if (ptr && ptr < end) {
		plen = ptr - s_url;
		host->auth = strndup(s_url, plen);
		s_url = ptr + 1;
	}

	/* check IPv6 domain version */
	if (*s_url == '[') {
		s_url++;
	}

	ptr = strchr(s_url, ']');
	if (!ptr) {
		ptr = s_url;
	}

	ptr = strchr(s_url, ':');
	if (ptr && ptr < end) {
		plen = (*(ptr - 1) != ']') ? ptr - s_url : ptr - s_url - 1;
		host->host = strndup(s_url, plen);
		plen = end - ++ptr;
		host->port = strndup(ptr, plen);
	} else {
		plen = (*(end - 1) != ']') ? end - s_url : end - s_url - 1;
		host->host = strndup(s_url, plen);
		if (host->proto == HTTPS) {
			host->port = strdup("443");
		} else {
			host->port = strdup("80");
		}
		       
	}
}

void host_clean(struct host *host)
{
	host->proto = NO_PROTO;
	ZSTREAM_FREE_STR(host->auth);
	ZSTREAM_FREE_STR(host->host);
	ZSTREAM_FREE_STR(host->port);
	ZSTREAM_FREE_STR(host->path);
	ZSTREAM_FREE_STR(host->url);
}

int host_check_https(int proto)
{
	if (proto == HTTPS) {
		return 1;
	} else {
		return 0;
	}
}
