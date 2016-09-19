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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

static const char urlencode_tbl[] = "0123456789ABCDEF";

char* zstream_urlencode(const char *in, int encode_plus) {
	char *out = malloc(strlen(in) * 3 + 1), *cout = out;
	const char *cin = in - 1;
	if (!out) {
		return NULL;
	}

	while (*++cin) {
		if (!isalnum(*cin) && *cin != '-' && *cin != '_'
		&& *cin != '.' && *cin != '~') {
			unsigned char *d = (unsigned char*)cin;
			*cout++ = '%';
			*cout++ = urlencode_tbl[*d >> 4];
			*cout++ = urlencode_tbl[*d & 0x0f];
		} else {
			*cout++ = (encode_plus && *cin == ' ') ? '+' : *cin;
		}
	}

	*cout = 0;
	return out;
}

char* zstream_urldecode(const char *in, int decode_plus) {
	char *out = malloc(strlen(in) + 1), *cout = out, dec[] = "00";
	const char *cin = in - 1;
	if (!out) {
		return NULL;
	}

	while (*++cin) {
		if (*cin == '%') {
			if (!isxdigit(cin[1]) || !isxdigit(cin[2])) {
				errno = EINVAL;
				free(out);
				return NULL;
			}
			dec[0] = *++cin;
			dec[1] = *++cin;
			unsigned char *co = (unsigned char*)(cout++);
			*co = strtol(dec, NULL, 16);
		} else {
			*cout++ = (decode_plus && *cin == '+') ? ' ' : *cin;
		}
	}

	*cout = 0;
	return out;
}


static const unsigned char b64encode_tbl[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* zstream_b64encode(const void *in, size_t *len) {
	size_t lenout, pad, i;
	const uint8_t *data = (const uint8_t*)in;

	lenout = *len / 3;
	lenout *= 4;
	pad = *len % 3;

	if (*len == 0) {
		return strdup("");
	} else if (pad) {
		lenout += 4;
	}

	char *out = malloc(lenout + 1);
	if (!out) {
		return NULL;
	}

	uint8_t *o = (uint8_t*)out;
	for (i = 0; i < *len; i += 3) {
		uint32_t cv = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
		*(o+3) = b64encode_tbl[ cv        & 0x3f];
		*(o+2) = b64encode_tbl[(cv >> 6)  & 0x3f];
		*(o+1) = b64encode_tbl[(cv >> 12) & 0x3f];
		*o     = b64encode_tbl[(cv >> 18) & 0x3f];
		o += 4;
	}

	if (pad) {
		uint32_t cv = data[*len-pad] << 16;
		*(o-1) = '=';
		*(o-2) = '=';
		if (pad == 2) {
			cv |= data[*len-pad+1] << 8;
			*(o-2) = b64encode_tbl[(cv >> 6) & 0x3f];
		}
		*(o-3) = b64encode_tbl[(cv >> 12) & 0x3f];
		*(o-4) = b64encode_tbl[(cv >> 18) & 0x3f];
	}

	out[lenout] = 0;
	*len = lenout;
	return out;
}

#ifdef BASE64_DECODE
static const unsigned char b64decode_tbl[] = {
	0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
	0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

void* zstream_b64decode(const char *in, size_t *len) {
	size_t lenout, i;

	if (*len == 0) {
		return strdup("");
	} else if (*len % 4) {
		errno = EINVAL;
		return NULL;
	}

	lenout = *len / 4 * 3;

	unsigned char *out = malloc(lenout);
	if (!out) {
		return NULL;
	}

	unsigned char *o = out;
	for (i = 0; i < *len; i += 4) {
		uint32_t cv = 0;
		for (int j = 0; j < 4; j++) {
			unsigned char c = in[i + j] - 43;
			if (c > 79 || (c = b64decode_tbl[c]) == 0xff) {
				free(out);
				errno = EINVAL;
				return NULL;
			}

			cv |= c;
			if (j != 3) {
				cv <<= 6;
			}
		}

		*(o+2) = (unsigned char)(cv & 0xff);
		*(o+1) = (unsigned char)((cv >>  8) & 0xff);
		*o     = (unsigned char)((cv >> 16) & 0xff);
		o += 3;
	}

	if (in[*len-1] == '=') {
		lenout--;
	}

	if (in[*len-2] == '=') {
		lenout--;
	}

	*len = lenout;
	return out;
}
#endif
