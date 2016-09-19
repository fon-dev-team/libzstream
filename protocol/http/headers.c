/*
 * headers.c: Managing HTTP headers and cookies
 * Copyright (C) 2016 Alejandro Martin <alejandro.martin@fon.com>
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

#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include "libubox/list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "headers.h"
#include <data.h>
#include <encoding.h>

#define DEFAULT_USERAGENT "zstream/1.0"
#define BAUTH_LENGTH 256

struct http_header {
	struct list_head _head;
	char *key;
	char *val;
};

struct http_cookie {
	struct list_head _head;
	char *name;
	char *value;
	char *domain;
	char *path;
	time_t expires;
	int secure;
};

#define CHECK_HEADER_FLAG(hdr, flag) \
	(hdr->headers_flags & flag)

static char *method_str(int method)
{
	switch (method) {
	case GET:
		return "GET";
	case POST:
		return "POST";
	case PUT:
		return "PUT";
	default:
		return "GET";
	}
}

/*
 * Header key is normilazed as Xxxx-Xxxx
 * first capital letter lower ther rest.
 * e.g. content-type normalized as Content-Type.
 */
static void normalize_tag(char *tag)
{
	int upper = 1;
	int i;
	
	for (i = 0; i < strlen(tag); i++) {
		tag[i] = (upper) ? toupper(tag[i]) : tolower(tag[i]);
		upper = !isalnum(tag[i]);
	}
}

/*
 * Sets basic header flags to check when the message is
 * compounded. If not the basic headers are automatically
 * set.
 */
static void set_headers_flags(int *flags, const char *key)
{
	if (!strcasecmp(key, "authorization")) {
		*flags |= HDR_AUTHORIZATION;
	} else if (!strcasecmp(key, "content-type")) {
		*flags |= HDR_CONTENT_TYPE;
	} else if (!strcasecmp(key, "content-length")) {
		*flags |= HDR_CONTENT_LENGTH;
	} else if (!strcasecmp(key, "expect")) {
		*flags |= HDR_EXPECT;
	} else if (!strcasecmp(key, "host")) {
		*flags |= HDR_HOST;
	} else if (!strcasecmp(key, "user-agent")) {
		*flags |= HDR_USER_AGENT;
	} else if (!strcasecmp(key, "range")) {
		*flags |= HDR_RANGE;
	} else if (!strcasecmp(key, "transfer-encoding")) {
		*flags |= HDR_TRANSFER_ENCODING;
	}
}

/*
 * Stores the header info in a queue to be used
 * when the HTTP message is compounded.
 */
int headers_add_header(struct list_head *list, int *hflags, const char *key, const char *val)
{
	struct http_header *hdr;
	
	hdr = (struct http_header *)calloc(1, sizeof(struct http_header));
	if (!hdr) {
		return -ENOMEM;
	}

	hdr->key = strndup(key, strlen(key));
	normalize_tag(hdr->key);
	hdr->val = strndup(val, strlen(val));
	list_add(&hdr->_head, list);
	if (hflags) {
		set_headers_flags(hflags, key);
	}
	return 0;
}

void headers_del_header(struct list_head *list, const char *key)
{
// TODO remove a specific header pointer by key
}

char *headers_get_header(struct list_head *list, const char *key)
{
	//TODO multiple values
	struct http_header *hdr;
	
	list_for_each_entry(hdr, list, _head) {
		if (!strncmp(hdr->key, key, strlen(hdr->key))) {
			return hdr->val;
		}
	}
	return NULL;
}

void headers_flush_headers(struct list_head *list)
{
	while (!list_empty(list)) {
		struct http_header *hdr =
			list_first_entry(list, struct http_header, _head);
		free(hdr->key);
		free(hdr->val);
		list_del(&hdr->_head);
		free(hdr);
	}
}

static void free_cookie(struct http_cookie *cookie)
{
	if (cookie->domain) {
		free(cookie->domain);
		cookie->domain = NULL;
	}
	if (cookie->name) {
		free(cookie->name);
		cookie->name = NULL;
	}
	if (cookie->path) {
		free(cookie->path);
		cookie->path = NULL;
	}
	if (cookie->value) {
		free(cookie->value);
		cookie->value = NULL;
	}
	free(cookie);
}

static void remove_duplicate_cookie(struct list_head *list, struct http_cookie *cookie)
{
	struct http_cookie *c;
	list_for_each_entry(c, list, _head) {
		if (!strcmp(c->domain, cookie->domain) &&
			!strcmp(c->name, cookie->name) &&
			!strcmp(c->path, cookie->path)) {
			list_del(&c->_head);
			free_cookie(c);
			break;
		}
	}
}

/*
 * Stores the cookie info in a queue to be used
 * when the HTTP message is compounded.
 */
int headers_add_cookie(struct list_head *list, char *c, char *host, char *path)
{
	struct http_cookie *cookie;
	size_t len;
	
	cookie = (struct http_cookie *)calloc(1, sizeof(struct http_cookie));
	if (!cookie) {
		return -ENOMEM;
	}

	len = strcspn(c, "=;");
	cookie->name = strndup(c, len);
	c += len;
	
	if (!cookie->name) {
		free_cookie(cookie);
		return -EPROTO;
	}

	if (*c == '=') {
		c++;
		len = strcspn(c, ";");
		cookie->value = strndup(c, len);
		c += len;
	}

	while (*(c += strspn(c, "; "))) {
		len = strcspn(c, "=;") + 1;
		char *val = c + len;
		size_t vlen = strcspn(val, ";");
		if (!strncasecmp("expires=", c, len)) {
			char date[32] = { 0 };
			strncpy(date, val, sizeof(date) - 1);
			struct tm t;
			cookie->expires = (strptime(date, "%a, %d %h %Y %T GMT", &t))
				? timegm(&t) : 0;
		} else if (!strncasecmp("domain=", c, len)) {
			if (!host || (val[0] == '.' && !strncasecmp(&val[1], host, vlen - 1))) {
				cookie->domain = strndup(val, vlen);
			}
		} else if (!strncasecmp("path=", c, len)) {
			if (!path || !strncasecmp(val, path, vlen)) {
				cookie->path = strndup(val, vlen);
			}
		} else if (!strncasecmp("secure;", c, len)) {
			cookie->secure = 1;
		}
		c = val + len;
	}

	if (!cookie->domain) {
		cookie->domain = strdup(host);
	}
	
	if (!cookie->path) {
		char *last = strrchr(path, '/');
		cookie->path = (!last) ? strdup("/") :
			strndup(path, last - path + 1);
	}
	
	remove_duplicate_cookie(list, cookie);

	if (!cookie->expires || (cookie->expires > time(NULL))) {
		list_add(&cookie->_head, list);
	} else {
		free_cookie(cookie);
	}
	return 0;		
}

void headers_flush_cookies(struct list_head *list)
{
	while (!list_empty(list)) {
		struct http_cookie *cookie =
			list_first_entry(list, struct http_cookie, _head);
		list_del(&cookie->_head);
		free_cookie(cookie);
	}
}

static char *b64encoded_auth(char *auth)
{
	char *a;
	char *r = NULL;
	
	if (!auth) {
		return NULL;
	}

	a = zstream_urldecode(auth, 0);	
	if (a) {
		size_t alen = strlen(a);
		r = zstream_b64encode(a, &alen);
		free(a);
	}

	return r;
}

/*
 * Sets the all headers info in the HTTP message.
 */
static void headers_set_headers(FILE *fd, struct list_head *list)
{
	struct http_header *hdr;

	list_for_each_entry(hdr, list, _head) {
		fprintf(fd, "%s: %s\r\n", hdr->key, hdr->val);
	}
}

/*
 * Sets the all cookie info in the HTTP message.
 */
static void headers_set_cookies(FILE *fd, struct list_head *list)
{
	struct http_cookie *cookie;
	int first_cookie = 1;
	
	list_for_each_entry(cookie, list, _head) {
		fprintf(fd, "%s%s=%s", (first_cookie) ? "Cookie: " : "; ",
			cookie->name, (cookie->value) ? cookie->value : "");
		first_cookie = 0;		
	}
}

/*
 * Sets the metainfo in the HTTP message.
 */
void headers_set_msg_headers(struct zstream *stream)
{
	struct host *host = &stream->host;
	
	fprintf(stream->fd, "%s %s HTTP/1.1\r\n", method_str(stream->action), host->path);

	if (!CHECK_HEADER_FLAG(stream, HDR_HOST)) {
		fprintf(stream->fd, "Host: %s:%s\r\n", host->host, host->port);
	}

	if (!CHECK_HEADER_FLAG(stream, HDR_AUTHORIZATION)) {
		char *bd_auth;
		char *ptr = NULL;
		if (stream->basic_user && stream->basic_pass ) {
			char bauth[BAUTH_LENGTH];
			snprintf(bauth, sizeof(bauth), "%s:%s", stream->basic_user, stream->basic_pass);
			ptr = bauth;
		} else if (host->auth) {
			ptr = host->auth;
		}

		/*
		 * b64encoded_auth reserves memory for bd_auth string. It must be freed
		 */
		bd_auth = b64encoded_auth(ptr);
		if (bd_auth) {
			fprintf(stream->fd, "Authorization: Basic %s\r\n", bd_auth);
			free(bd_auth);
		}
	}


	if (!CHECK_HEADER_FLAG(stream, HDR_USER_AGENT)) {
		fprintf(stream->fd, "User-Agent: %s\r\n", DEFAULT_USERAGENT);
	}

	if ((stream->action == POST) || (stream->action == PUT)) {
		if (!CHECK_HEADER_FLAG(stream, HDR_CONTENT_TYPE) && stream->action == POST) {
			fputs("Content-Type: application/x-www-form-urlencoded\r\n", stream->fd);
		}

		if (!CHECK_HEADER_FLAG(stream, HDR_EXPECT)) {
			fputs("Expect: 100-continue\r\n", stream->fd);
		}

		if (!CHECK_HEADER_FLAG(stream, (HDR_TRANSFER_ENCODING | HDR_CONTENT_LENGTH))) {
			if (stream->msg_size > 0) {
				fprintf(stream->fd, "Content-Length: %llu\r\n", (unsigned long long)stream->msg_size);
			} else {
				fputs("Transfer-Encoding: chunked\r\n", stream->fd);
			}
		}
	}

	/* Set user defined header values */
	headers_set_headers(stream->fd, &stream->send_headers);
	headers_set_cookies(stream->fd, &stream->cookies);
	
	fputs("\r\n", stream->fd);
}
