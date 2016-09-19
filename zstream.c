/*
 * zstream.c - Minimalistic HTTP library
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <syslog.h>
#include <unistd.h>

#include <data.h>
#include <http.h>
#include <headers.h>
#include <tls.h>
#include <host.h>

#include "zstream.h"

zstream_t *zstream_init(void)
{
	zstream_t *stream = calloc(1, sizeof(zstream_t));
	if (!stream) {
		return NULL;
	}

	/* GET is the action by default */
	stream->action = GET;
	INIT_LIST_HEAD(&stream->send_headers);
	INIT_LIST_HEAD(&stream->cookies);
	INIT_LIST_HEAD(&stream->receive_headers);

	return stream;
}

void zstream_clean(zstream_t *stream)
{
	zstream_close(stream);

	headers_flush_headers(&stream->send_headers);
	headers_flush_headers(&stream->receive_headers);
	headers_flush_cookies(&stream->cookies);

	stream->action = 0;
	ZSTREAM_FREE_STR(stream->basic_user);
	ZSTREAM_FREE_STR(stream->basic_pass);
	
	host_clean(&stream->host);
	tls_clean(&stream->tls);
	free(stream);
}

void zstream_setopt(zstream_t *stream, int type, const char *option)
{
	char *endptr;
	      
	if (!stream) {
		return;
	}
	
	switch (type) {
	case ZSTREAM_OPT_URL:
		host_url_parse(&stream->host, option);
		break;
	case ZSTREAM_OPT_TOUT:
		stream->timeout = strtol(option, &endptr, 10);
		break;
	case ZSTREAM_OPT_POST:
		stream->action = POST;
		break;
	case ZSTREAM_OPT_GET:
		stream->action = GET;
		break;
	case ZSTREAM_OPT_PUT:
		stream->action = PUT;
		break;
	case ZSTREAM_OPT_BASICAUTH_USER:
		stream->basic_user = strdup(option);
		break;
	case ZSTREAM_OPT_BASICAUTH_PASS:
		stream->basic_pass = strdup(option);
		break;
	case ZSTREAM_OPT_POSTSIZE:
		stream->action = POST;
		stream->msg_size = strtol(option, &endptr, 10);
		break;
	case ZSTREAM_OPT_POSTFIELDS:
		stream->action = POST;
		stream->post_data = (char *)option;
		break;
	case ZSTREAM_SSL_VERIFYPEER:
		stream->tls.verify_peer = strtol(option, &endptr, 10);
		break;
	case ZSTREAM_SSL_VERIFYHOST:
		stream->tls.verify_host = strtol(option, &endptr, 10);
		break;
	case ZSTREAM_CRLFILE:
		stream->tls.crl_file = strdup(option);
		break;
	case ZSTREAM_CAPATH:
		stream->tls.ca_path = strdup(option);
		break;
	case ZSTREAM_CAFOLDER:
		stream->tls.ca_folder = strdup(option);
		break;
	default:
		syslog(LOG_ERR, "%s: Invalid HTTP option %d", __FUNCTION__, type);
	}
}

void zstream_setwritecb(zstream_t *stream, data_cb_t *cb)
{
	stream->cb = cb;
}

int zstream_open(zstream_t *stream)
{
	int err = 0;
	
	if (!stream->socket) {
		err = http_connect(stream);
	}
		
	return err;
}

void zstream_close(zstream_t *stream)
{
	http_close(stream);
}

int zstream_add_header(zstream_t *stream, const char *key, const char *val)
{
	int err = 0;
	
	err = headers_add_header(&stream->send_headers, &stream->headers_flags, key, val);
	return err;
}

int zstream_add_cookie(zstream_t *stream, const char *cookie)
{
	int err = 0;

	err = headers_add_cookie(&stream->cookies, (char *)cookie, stream->host.host, stream->host.path); //TODO check defaults
	return err;
}

void zstream_flush_headers(zstream_t *stream)
{
	headers_flush_headers(&stream->send_headers);
	headers_flush_headers(&stream->receive_headers);
}

void zstream_flush_cookies(zstream_t *stream)
{
	headers_flush_cookies(&stream->cookies);
}

/*
 * Performs the action sets by user (GET action by default)
 * If the connection has not been opened previously then
 * we assume the action must open the connection and
 * close it after performs it. Otherwise, if the connection
 * is opened it remains opened for future performs.
 */
int zstream_perform(zstream_t *stream)
{
	int one_shot = 0;
	int err = 0;
	
	if (!stream->socket) {
		err = http_connect(stream);
		if (err) {
			syslog(LOG_ERR, "%s: Error connecting to server", __FUNCTION__);
			return -1;
		}
		one_shot = 1;
	}

	err = http_perform(stream);

	if (one_shot) {
		http_close(stream);
	}

	return err;
}
