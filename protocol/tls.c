/*
 * tls.c - Managing HTTPS connections. It gets and stores
 * CRL files and checks certificates.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <libubox/usock.h>
#include <stdbool.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <data.h>
#include "tls.h"
#include <zstream.h>


#define MAX_RESPONSE 10000
#define SSL_CONNECT_RETRIES 5
#define SSL_CONNECT_INTERVAL 1

static char *crlfile = NULL;
static int crl_index = 0;
static char buffer_file[MAX_RESPONSE];
static char *r_index;

#define SSL_LOG_ERR() syslog(LOG_ERR, "%s: SSL error: %s", __FUNCTION__, \
				ERR_error_string(ERR_get_error(), NULL))

/* TLS stdio read fopencookie() callback */
static ssize_t tls_read(void *cookie, char *buf, size_t size)
{
	SSL *ssl = cookie;
	int status = SSL_read(ssl, buf, size);
	if (status < 0) {
		status = SSL_get_error(ssl, status);
		if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE) {
			errno = EAGAIN;
			return -1;
		} else {
			return 0;
		}
	}
	return status;
}

/* TLS stdio write fopencookie() callback */
static ssize_t tls_write(void *cookie, const char *buf, size_t size)
{
	SSL *ssl = cookie;
	int status = SSL_write(ssl, buf, size);
	if (status < 0) {
		status = SSL_get_error(ssl, status);
		errno = (status == SSL_ERROR_WANT_READ||status == SSL_ERROR_WANT_WRITE)
			? EAGAIN : EPIPE;
		return -1;
	}
	return status;
}

/*
 * Overwrite socket functions
 */
static cookie_io_functions_t io = {
	.read = tls_read,
	.write = tls_write
};

static void write_callback(char *buffer, int size)
{
	memcpy(r_index, buffer, size);
	r_index += size;
}

/*
 * Write CRL file. The CRL file will be used by
 * SSL library to check the server certificate.
 */
static void get_crl_file(char *url, FILE *pem_file)
{
	zstream_t *stream = NULL;
	int len = 0;
	memset(buffer_file, 0, MAX_RESPONSE);
	r_index = buffer_file;
	
	if (!url || !strlen(url)) {
		return;
	}
	
	syslog(LOG_DEBUG, "Retrieving CRL at %s", url);

	stream = zstream_init();
	if (!stream) {
		syslog(LOG_ERR, "%s: Error opening %s", __FUNCTION__, url);
		return;
	}

	zstream_setopt(stream, ZSTREAM_OPT_URL, url);
	zstream_setwritecb(stream, &write_callback);
	zstream_perform(stream);
	zstream_flush_headers(stream);
	
	zstream_clean(stream);
		
	const char pemhdr[] = "-----BEGIN X509 CRL-----";
	size_t pemhdr_len = sizeof(pemhdr) - 1;
	len = r_index - buffer_file;
	bool is_pem = len > pemhdr_len && !strncmp(buffer_file, pemhdr, pemhdr_len);
	
	X509_CRL *crl = NULL;
	const unsigned char *dbuf = (const unsigned char*)buffer_file;
	
	if (is_pem) {
		BIO *bio = BIO_new_mem_buf(dbuf, len);
		crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
		BIO_free(bio);
	} else {
		crl = d2i_X509_CRL(NULL, &dbuf, len);
	}
	
	PEM_write_X509_CRL(pem_file, crl);
	X509_CRL_free(crl);
}

static void openssl_crl(SSL *ssl, FILE *pem_file)
{
	int i;
	STACK_OF(X509) *certs = SSL_get_peer_cert_chain(ssl);
	
	for (i = 0; i < sk_X509_num(certs); ++i) {
		STACK_OF(DIST_POINT) *cdps = X509_get_ext_d2i(sk_X509_value(certs, i),
							NID_crl_distribution_points, NULL, NULL);
		DIST_POINT *dp = NULL;
		while ((dp = sk_DIST_POINT_pop(cdps))) {
			STACK_OF(GENERAL_NAME) *names = dp->distpoint->name.fullname;
			if (sk_GENERAL_NAME_num(names) < 1) {
				continue;
			}
			
			GENERAL_NAME *name = sk_GENERAL_NAME_value(names, 0);
			if (name->type != GEN_URI) {
				continue;
			}

			ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
			get_crl_file((char*)uri->data, pem_file);

			DIST_POINT_free(dp);
		}
		sk_DIST_POINT_free(cdps);
	}	
}

static int tls_connect(SSL *ssl, int sock)
{
	int tries = SSL_CONNECT_RETRIES;
	int flags;
	int err = -1;
	
	flags = fcntl(sock, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(sock, F_SETFL, flags);
	
	while (tries) {
		int e;
		int ret;

		ret = SSL_connect(ssl);
		if (ret >= 1) {
			err = 0;
			break;
		}

		e = SSL_get_error(ssl, ret);
		if (e != SSL_ERROR_WANT_CONNECT && e != SSL_ERROR_WANT_ACCEPT &&
			e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
			/* Error we want to fail otherwise retry SSL_connect */
			syslog(LOG_ERR, "%s: SSL_connect fail error %d", __FUNCTION__, e);
			SSL_LOG_ERR();
			break;
		}
		tries--;
		sleep(SSL_CONNECT_INTERVAL);
	}
	
	flags = fcntl(sock, F_GETFL, 0);
	flags &= ~O_NONBLOCK;
	fcntl(sock, F_SETFL, flags);
	return err;
}

static int zstream_tls_get_crl_file(char *host, char *port, const char *file)
{
	int sock;
	SSL_CTX *ctx;
	SSL *ssl;
	int err;
	
	sock = usock(USOCK_TCP, host, port);
	if (sock < 0) {
		syslog(LOG_ERR, "Failed to connect to server %s:%s", host, port);
		return -1;
	}

	SSL_library_init();
	ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	crlfile = strdup(file);
	
	ssl = SSL_new(ctx);	
	SSL_set_fd(ssl, sock);

	err = tls_connect(ssl, sock);
	if (err) {
		syslog(LOG_ERR, "%s: Error SSL connect", __FUNCTION__);
		return -1;
	}
	
	FILE *pem_file = fopen(crlfile, "w");
	openssl_crl(ssl, pem_file);
	fflush(pem_file);
	fclose(pem_file);
	
	close(sock);
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	free(crlfile);
	crlfile = NULL;
	return 0;
}

static int tls_set_crl(struct tls *tls, char *domain, char *port)
{
	int err = 0;
	int len = 0;
	char *file_name = strdup(tls->crl_file);
	
	if (!domain) {
		free(file_name);
		return -1;
	}

	crl_index = 0;

	if (!port) {
		port = strdup("443");
	}

	if (!file_name) {
		/* constant length strlen(/tmp/ + /crl.pem + EOL) =  15 */
		len = strlen(domain) + strlen(port) + 15;
		file_name = (char *)malloc(len);
		memset(file_name, 0, len);
		snprintf(file_name, len - 1, "/tmp/%s/%scrl.pem", domain, port);
		char *folder = strdup(file_name);
		mkdir(dirname(folder), 777);
		free(folder);
	}
	
	err = zstream_tls_get_crl_file(domain, port, file_name);
	free(file_name);
	return err;
}

void tls_close(struct tls *tls)
{
	if (tls->ssl) {
		SSL_shutdown(tls->ssl);
		SSL_free(tls->ssl);
		tls->ssl = NULL;
	}

	if (tls->ctx) {
		SSL_CTX_free(tls->ctx);
		tls->ctx = NULL;
	}
}

static int tls_set_verify_peer(struct tls *tls, char *host, char *port)
{
	int err = 0;
	
	if (tls->verify_peer) { 
		SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER, NULL);
		
		if (tls->ca_path && strlen(tls->ca_path)) {
			SSL_CTX_load_verify_locations(tls->ctx, tls->ca_path, NULL);
		} else if (tls->ca_folder && strlen(tls->ca_folder)) {
			SSL_CTX_load_verify_locations(tls->ctx, NULL, tls->ca_folder);
		} else {
			syslog(LOG_ERR, "%s: No verify location set", __FUNCTION__);
		}

		err = tls_set_crl(tls, host, port);
		
		if (tls->crl_file) {
			X509_LOOKUP *lookup = X509_STORE_add_lookup(
				SSL_CTX_get_cert_store(tls->ctx), X509_LOOKUP_file());
			X509_STORE_set_flags(SSL_CTX_get_cert_store(tls->ctx),
					X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
			X509_load_crl_file(lookup, tls->crl_file, X509_FILETYPE_PEM);
		}
		
	}
	return err;
}

static int tls_set_verify_host(struct tls *tls, char *domain)
{
	if (tls->verify_host) {
		X509_VERIFY_PARAM *param = NULL;
		param = SSL_get0_param(tls->ssl);
		X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(param, domain, 0);
		SSL_set_tlsext_host_name(tls->ssl, domain);
	}
	return 0;
}

static FILE *tls_fdopen(struct tls *tls, int socket)
{
	int err = 0;

	err = tls_connect(tls->ssl, socket);
	if (err) {
		return NULL;
	}
	
	return fopencookie(tls->ssl, "r+", io);
}

int tls_ssl_init(struct tls *tls, int socket)
{
	if (!tls->ctx) {
		return -1;
	}
	
	tls->ssl = SSL_new(tls->ctx);
	SSL_set_fd(tls->ssl, socket);
	return 0;
}

static void tls_ssl_init_ctx(struct tls *tls)
{
	SSL_library_init();
	tls->ctx = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_NONE, NULL);
	return;
}

void tls_clean(struct tls *tls)
{
	ZSTREAM_FREE_STR(tls->ca_path);
	ZSTREAM_FREE_STR(tls->ca_folder);
	ZSTREAM_FREE_STR(tls->crl_file);
}

FILE *tls_init(struct tls *tls, int socket, char *host, char *port)
{
	int err = 0;
	FILE *fd = NULL;
	
	tls_ssl_init_ctx(tls);
	err = tls_set_verify_peer(tls, host, port);
	if (err) {
		goto err;
	}

	tls_ssl_init(tls, socket);
	err = tls_set_verify_host(tls, host);
	if (err) {
		goto err;
	}

	fd = tls_fdopen(tls, socket);
	if (!fd) {
		goto err;
	}
	
	return fd;
err:
	tls_close(tls);
	return NULL;
}

int tls_read_response(struct zstream *stream, char *buffer, int size)
{
	struct tls *tls = &stream->tls;
	SSL *ssl = tls->ssl;
	int bytes;

	bytes = SSL_read(ssl, buffer, size);
	return bytes;
}
