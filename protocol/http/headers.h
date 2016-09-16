/*
 * headers.h: Managing HTTP headers and cookies
 * Copyright (C) 2016 Alejandro Martin <alejandro.martin@fon.com>
 * Copyright (C) 2011 Steven Barth <steven@midlink.org>
 * Copyright (C) 2011 John Crispin <blogic@openwrt.org>
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

#ifndef __ZSTREAM_HEADERS_H__
#define __ZSTREAM_HEADERS_H___

#ifndef typeof
#define typeof __typeof__
#endif

#include <libubox/list.h>
#include <data.h>

#define HDR_AUTHORIZATION	0x0001
#define HDR_CONTENT_TYPE	0x0002
#define HDR_CONTENT_LENGTH	0x0004
#define HDR_EXPECT		0x0008
#define HDR_HOST		0x0010
#define HDR_USER_AGENT		0x0020
#define HDR_RANGE		0x0040
#define HDR_TRANSFER_ENCODING	0x0080

int headers_add_header(struct list_head *list, int *hflags, const char *key, const char *val);
void headers_del_header(struct list_head *list, const char *key);
char *headers_get_header(struct list_head *list, const char *key);
void headers_flush_headers(struct list_head *list);

int headers_add_cookie(struct list_head *list, char *c, char *host, char *path);
void headers_flush_cookies(struct list_head *list);

void headers_set_msg_headers(struct zstream *stream);

#endif
