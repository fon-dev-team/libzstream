/*
 * http.h: Managing HTTP protocol. Connects, sends and receives the
 * HTTP messages
 * Copyright (C) 2016 Alejandro Martin <alejandro.martin@fon.com>
 * Copyright (C) 2010 Steven Barth <steven@midlink.org>
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

#ifndef ZSTREAM_HTTP_H_
#define ZSTREAM_HTTP_H_

#include <data.h>

#define HTTP_CODE_BADREQUEST 400
#define HTTP_CODE_UNAUTHORIZED 401
#define HTTP_CODE_FORBIDDEN 403
#define HTTP_CODE_NOTFOUND 404

#define HTTP_CODE_MOVEPERM 301
#define HTTP_CODE_FOUND 302
#define HTTP_CODE_SEEOTHER 303
#define HTTP_CODE_NOTMODIFIED 304
#define HTTP_CODE_TEMPREDIR 307

#define HTTP_CODE_OK 200
#define HTTP_CODE_CREATED 201
#define HTTP_CODE_ACCEPTED 202
#define HTTP_CODE_NOCONTENT 204
#define HTTP_CODE_PARTIALCONTENT 206

#define HTTP_CODE_CONTINUE 100

int http_perform(struct zstream *stream);
int http_connect(struct zstream *stream);
void http_close(struct zstream *stream);

#endif
