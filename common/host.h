/*
 * host.h - Parsing host input to get its components.
 * Copyrigth (C) 2016 Alejandro Martin <alejandro.martin@fon.com>
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

#ifndef __ZSTREAM_UTILS_H__
#define __ZSTREAM_UTILS_H__

#include <data.h>

void host_url_parse(struct host *host, const char *src);
void host_clean(struct host *host);
int host_check_https(int proto);

#endif
