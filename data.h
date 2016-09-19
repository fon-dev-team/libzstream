/*
 * data.h - zstream library structs
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

#ifndef DATA_H_
#define DATA_H_

#include <stdlib.h>
#include <libubox/list.h>
#include <openssl/ssl.h>
#include "zstream.h"

typedef int (read_function_t)(struct zstream *stream, char *buffer, int size);

enum http_action {
	GET,
	POST,
	PUT
};

struct host {
	char *url;

	int proto;
	char *host;
	char *port;
	char *auth;
	char *path;
};

struct tls {
	int verify_peer;
	int verify_host;
	char *ca_path;
	char *ca_folder;
	char *crl_file;
	SSL_CTX *ctx;
	SSL *ssl;
};

struct zstream {
	int action;

	char *basic_user;
	char *basic_pass;
	
	struct host host;
	struct tls tls;
	
	char *post_data;
	int msg_size;
	data_cb_t *cb;

	int timeout;
	struct list_head send_headers;
	struct list_head cookies;
	
	int headers_flags;
	int size;
	int socket;
	FILE *fd;
	
	int response_status;
	read_function_t *read_function;
	struct list_head receive_headers;
};

#define ZSTREAM_FREE_STR(name)			\
	if (name) {				\
		free(name);			\
		name = NULL;			\
	}

#endif

