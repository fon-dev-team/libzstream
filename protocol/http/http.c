/*
 * http.c: Managing HTTP protocol. Connects, sends and receives the
 * HTTP messages
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include "libubox/usock.h"
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>

#include <data.h>
#include <tls.h>
#include <host.h>

#include "headers.h"
#include "http.h"

#define BUFFER_SIZE 8192
#define CRLF "\r\n"

/*
 * "\r\n" size in bytes
 */
#define CRLF_SIZE 2
#define CHECK_CRLF(p) (p[0] == '\r' && p[1] == '\n')

enum response_state {
	RESP_CODE,
	RESP_HEADER,
	RESP_CHUNK_SIZE,
	RESP_CHUNK_DATA,
	RESP_CHUNK_CRLF,
	RESP_CHUNK_TRAILER,
	RESP_BODY
};

struct http_response {
	int completed;
	int status;
	int code;
	int chunked;
	int size;
	int length;
	int remaining;
	char *mtime;
};

static int http_read_response(struct zstream *stream, char *buffer, int size)
{
	int bytes;

	bytes = recv(stream->socket, buffer, size, MSG_DONTWAIT);
	return bytes;
}

/*
 * Opens the connection with a server pointed by stored
 * host and port.
 * The connection remains opened until the user closes it.
 * If protocol is HTTPS starts TLS session.
 */
int http_connect(struct zstream *stream)
{
	struct host *host = &stream->host;
	
	if (!stream || !host->host || !host->port) {
		syslog(LOG_ERR, "%s: No stream, domain or port", __FUNCTION__);
		goto err;
	}
	
	stream->socket = usock(USOCK_TCP, host->host, host->port);
	if (stream->socket == -1) {
		goto err;
	}

	if (host_check_https(host->proto)) {
		stream->fd = tls_init(&stream->tls, stream->socket, host->host, host->port);
		stream->read_function = tls_read_response;
	} else {
		stream->fd = fdopen(stream->socket, "r+");
		stream->read_function = http_read_response;
	}

	if (!stream->fd) {
		goto err;
	}
	
	setvbuf(stream->fd, NULL, _IOFBF, BUFFER_SIZE);
	stream->response_status = RESP_CODE;
	return 0;
err:
	http_close(stream);
	return -1;
}

void http_close(struct zstream *stream)
{
	tls_close(&stream->tls);
	
	if (stream->fd) {
		fclose(stream->fd);
		stream->fd = NULL;
	}

	if (stream->socket) {
		close(stream->socket);
		stream->socket = 0;
	}
}

/*
 * Parses metadata info, storing headers and cookies.
 */
static int zstream_http_parse_header(struct zstream *stream, struct http_response *response, char *line, int l)
{
	struct host *host = &stream->host;
	char *endptr;
	int err = -1;
	char *j = strndup(line, l);
	char *c = strchr(j, ':');

	if (!c) {
		goto exit;
	}
	
	*c = 0;
	while (isspace(*++c));
	/* c points to value after : character */

	err = headers_add_header(&stream->receive_headers, NULL, j, c); //TODO receive flags
	if (err) {
		goto exit;
	}
	
	if (!strcasecmp(j, "set-cookie")) {
		err = headers_add_cookie(&stream->cookies, c, host->host, host->path);
		if (err) {
			goto exit;
		}
	} else if (!strcasecmp(j, "transfer-encoding")) {
		response->chunked = 1;
	} else if (!strcasecmp(j, "content-length")) {
		response->remaining = strtol(c, &endptr, 10);
		
	}
	
	err = 0;
exit:
	free(j);
	return err;
	
}

/*
 * Converts HTTP response code into linux system error code.
 */
static int zstream_http_parse_code(int code)
{
	int res = 0;
	switch (code) {
	case HTTP_CODE_BADREQUEST:
		res = -EINVAL;
		break;
	case HTTP_CODE_UNAUTHORIZED:
	case HTTP_CODE_FORBIDDEN:
		res = -EACCES;
		break;
	case HTTP_CODE_NOTFOUND:
		res = -ENOENT;
		break;
	case HTTP_CODE_MOVEPERM:
	case HTTP_CODE_FOUND:
	case HTTP_CODE_SEEOTHER:
	case HTTP_CODE_NOTMODIFIED:
	case HTTP_CODE_TEMPREDIR:
		res = -EXDEV;
		break;
	case HTTP_CODE_OK:
	case HTTP_CODE_CREATED:
	case HTTP_CODE_ACCEPTED:
	case HTTP_CODE_NOCONTENT:
	case HTTP_CODE_PARTIALCONTENT:
	case HTTP_CODE_CONTINUE:
		res = 0;
		break;
	default:
		res = -EPROTO;
		break;
	}

	return res;
} 

/*
 * Parse HTTP response to get response code
 */
static int zstream_http_get_code(char *token, int *code)
{
	int val;
	char http[32];
	int res = 0;

	res = sscanf(token, "%s %d", http, &val);
	if (res == EOF || res != 2) {
		syslog(LOG_ERR, "%s: Error getting HTTP code, %s", __FUNCTION__, strerror(errno));
		return -1;
	}

	res = zstream_http_parse_code(val);
	*code = val;
	return res;
}

static int zstream_http_get_chunk_size(char *token, int *size)
{
	int val;
	int res = 0;
	
	res = sscanf(token, "%X\r\n", &val);
	if (res == EOF || res != 1) {
		syslog(LOG_ERR, "%s: Error getting chunk size, %s", __FUNCTION__, strerror(errno));
		return -1;
	}

	*size = val;
	return 0;
}

static int get_token_length(char *begin, char *end, int def)
{
	int res = def;
	if (end) {
		/* token length plus \r\n bytes size */
		res = end - begin + CRLF_SIZE;
	}
	return res;
}

/*
 * State machine to parse HTTPS server response, and
 * sets the end of body (when get the last chunk or the received body),
 * sending data to user through the set callback
 * E.g. of http response
 * HTTP/1.1 200 OK
 * Date: Mon, 23 May 2005 22:38:34 GMT
 * Content-Type: text/html; charset=UTF-8
 * Content-Encoding: UTF-8
 * Content-Length: 138
 * Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
 * Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
 * ETag: "3f80f-1b6-3e1cb03b"
 * Accept-Ranges: bytes
 * Connection: close
 *
 * <html>
 * <head>
 *  <title>An Example Page</title>
 * </head>
 * <body>
 *  Hello World, this is a very simple HTML document.
 * </body>
 * </html>
 *
 * 1. Get response code
 * 2. Get metadata
 * 3. Get body info and send it to user
 */
static int zstream_http_parse_response(struct zstream *stream, struct http_response *response,
				char *buffer, int size)
{
	char *p = buffer;
	char *q = NULL;
	int length = size;
	int err;

	while (size > 0) {		
		switch (stream->response_status) {
		case RESP_CODE:
			q = strstr(p, CRLF);
			err = zstream_http_get_code(p, &response->code);
			if (err) {
				syslog(LOG_ERR, "%s: HTTP code response %d, %s",
					__FUNCTION__, response->code, strerror(err));
				return err;
			}
			
			stream->response_status = RESP_HEADER;
			length = get_token_length(p, q, length);
			break;
		case RESP_HEADER:
			q = strstr(p, CRLF);
			if (CHECK_CRLF(p)) {
				if (response->code == HTTP_CODE_NOCONTENT) {
					response->completed = 1;
					break;
				} else if (response->code == HTTP_CODE_CONTINUE) {
					stream->response_status = RESP_CODE;
				} else {
					stream->response_status = (response->chunked) ?
						RESP_CHUNK_SIZE : RESP_BODY;
				}
			} else {
				/* 
				 * http parse modifies the stream. We need to get the strlen before parsing 
				 * We assume that the last character is '\r'
				 */
				zstream_http_parse_header(stream, response, p, q - p);
			}
			length = get_token_length(p, q, length);
			break;
		case RESP_CHUNK_SIZE:
			q = strstr(p, CRLF);
			err = zstream_http_get_chunk_size(p, &response->remaining);
			if (err) {
				syslog(LOG_ERR, "%s: HTTP chunk size %d, %s",
					__FUNCTION__, response->remaining, strerror(err));
				return -EPROTO;
			}
			stream->response_status = RESP_CHUNK_DATA;
			if (response->remaining == 0) {
				//TODO chunk trailer
				response->completed = 1;
				length = size;
				break;
			}
			length = get_token_length(p, q, length);
			break;
		case RESP_CHUNK_DATA:
			if (response->remaining <= size) {
				stream->cb(p, response->remaining);
				length = response->remaining;
				response->remaining = 0;
				stream->response_status = RESP_CHUNK_CRLF;
			} else {
				stream->cb(p, size);
				response->remaining -= size;
				length = size;
			}
			break;
		case RESP_CHUNK_CRLF:
			if (!CHECK_CRLF(p)) {
				syslog(LOG_DEBUG, "%s: chunk CRLF error", __FUNCTION__);
				return -EPROTO;
				
			}
			length = CRLF_SIZE;
			stream->response_status = RESP_CHUNK_SIZE;
			break;
		case RESP_BODY:
			if (response->remaining <= size) {
				stream->cb(p, response->remaining);
				response->remaining = 0;
			} else {
				stream->cb(p, size);
				response->remaining -= size;
			}
			if (response->remaining <= 0) {
				/* Fully completed or not content-length */
				response->completed = 1;
			}
			length = size;
			break;
		default:
			syslog(LOG_ERR, "%s: Error in response status state machine", __FUNCTION__);
			return -1;
		}
		
		p += length;
		size -= length;	
	}

	return 0;
}

static int zstream_http_get_response(struct zstream *stream, struct http_response *response)
{
	int err = 0;
	char lbuf[BUFFER_SIZE];
	int bytes = 0;
	int tbytes = 0;
	
	if (!stream->fd) {
		return -1;
	}

	memset(lbuf, 0, sizeof(lbuf));

	while ((bytes = stream->read_function(stream, lbuf, BUFFER_SIZE - 1)) > 0) {
		err = zstream_http_parse_response(stream, response, lbuf, bytes);
		if (err) {
			syslog(LOG_ERR, "%s: Protocol error %s", __FUNCTION__, strerror(errno));
			break;
			
		}
		memset(lbuf, 0, sizeof(lbuf));
		tbytes += bytes;
	}

	return err;
}

/*
 * Waits for the HTTP response until the end of the
 * message is reached or timeout
 * If the connection is HTTPS we must set the non block
 * flag of the socket due to TLS issues.
 */
static int zstream_http_read(struct zstream *stream)
{
	int err = 0;
	int poll_fd;
	struct epoll_event event;
	struct epoll_event *events;
	int flags;
	
	poll_fd = epoll_create1(0);

	if (host_check_https(stream->host.proto)) {
		flags = fcntl(stream->socket, F_GETFL, 0);
		flags |= O_NONBLOCK;
		fcntl(stream->socket, F_SETFL, flags);
	}
	
	event.data.fd = stream->socket;
	event.events = EPOLLIN | EPOLLET;
	err = epoll_ctl(poll_fd, EPOLL_CTL_ADD, stream->socket, &event);
	events = calloc(1, sizeof(struct epoll_event));

	struct http_response response;
	memset(&response, 0, sizeof(struct http_response));
	while (1) {
		int n;
		int i;
		n = epoll_wait(poll_fd, events, 1, (stream->timeout) ? stream->timeout * 1000 : -1);
		if (n == 0) {
			syslog(LOG_ERR, "%s: Epoll timeout", __FUNCTION__);
			break;
		}
		
		for (i = 0; i < n; i ++) {
			if ((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP) ||
				(!(events[i].events & EPOLLIN))) {
				syslog(LOG_ERR, "%s: Error in epoll", __FUNCTION__);
				continue;
			} else if (stream->socket == events[i].data.fd) {
				err = zstream_http_get_response(stream, &response);
				break;
			}
			
		}
		
		if (err || response.completed) {
			// TODO RESPONSE status in response
			stream->response_status = RESP_CODE;
			break;
		}
		
	}

	if (host_check_https(stream->host.proto)) {
		flags = fcntl(stream->socket, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(stream->socket, F_SETFL, flags);
	}
	
	return err;
}
	
int http_perform(struct zstream *stream)
{
	int err = 0;

	headers_set_msg_headers(stream);
	
	//TODO write chunks
	
	switch (stream->action) {
	case GET:
		fflush(stream->fd);
		err = zstream_http_read(stream);
		break;
	case POST:
	case PUT:
		if (stream->post_data && stream->msg_size > 0) {
			fputs(stream->post_data, stream->fd);
		}
		fflush(stream->fd);
		err = zstream_http_read(stream);
		break;
	default:
		syslog(LOG_ERR, "Not supported action %d", stream->action);
		err = -1;
	}
	
	return err;		
}
