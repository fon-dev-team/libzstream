/*
 * encoding.c - HTTP, B64 encoding stuff
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

#ifndef __ZSTREAM_ENCODING_H__
#define __ZSTREAM_ENCODING_H__

char* zstream_urlencode(const char *in, int encode_plus);
char* zstream_urldecode(const char *in, int decode_plus);
char* zstream_b64encode(const void *in, size_t *len);
void* zstream_b64decode(const char *in, size_t *len);

#endif
