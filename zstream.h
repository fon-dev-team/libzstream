/**
 * \addtogroup zstream
 * @{
 *
 * Micro HTTP library
 */
/*
 * zstream.h - Minimalistic HTTP library
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

#ifndef ZSTREAM_H_
#define ZSTREAM_H_

typedef struct zstream zstream_t;
typedef void (data_cb_t)(char *buffer, int size);

/**
 * @brief Valid options to be set
 */
enum zstream_opts {
	/**
	 * @brief Provide the URL to use in the request.
	 * scheme://[user:pass@]host[:port]/[path]
	 * Scheme value must be https or http (http is set otherwise)
	 * If port is not provided there are two options, 443 is set if
	 * https scheme is set, 80 in other cases.
	 */
	ZSTREAM_OPT_URL,
	/**
	 * Time allowed to wait for HTTP response.
	 */
	ZSTREAM_OPT_TOUT,
	/**
	 * @brief Make a HTTP POST request.
	 */
	ZSTREAM_OPT_POST,
	/**
	 * @brief Make a HTTP GET request.
	 * This is the default request value.
	 */
	ZSTREAM_OPT_GET,
	/**
	 * @brief Make a HTTP PUT request.
	 */
	ZSTREAM_OPT_PUT,
	/**
	 * @brief Size of POST data.
	 * It sets ZSTREAM_OPT_POST option automatically.
	 */
	ZSTREAM_OPT_POSTSIZE,
	/**
	 * @brief Pointing to the full data to send in a HTTP POST operation.
	 * It sets ZSTREAM_OPT_POST option automatically.
	 */	
	ZSTREAM_OPT_POSTFIELDS,
	/**
	 * @brief Username to be used for HTTP Basic authentication header
	 */
	ZSTREAM_OPT_BASICAUTH_USER,
	/**
	 * @brief Password to be used for HTTP Basic authentication header
	 */
	ZSTREAM_OPT_BASICAUTH_PASS,
	/**
	 * @brief Verifies the authenticity of the peer's certificate.
	 */
	ZSTREAM_SSL_VERIFYPEER,
	/**
	 * @brief Verifies that the server cert is for the server it is known as.
	 * It means it has to have the same name in the certificate as is in the URL you operate against.
	 */
	ZSTREAM_SSL_VERIFYHOST,
	/**
	 * @brief Specifies a Certificate Revocation List file.
	 * This option makes sense only when used in combination with the ZSTREAM_SSL_VERIFYPEER option.
	 */
	ZSTREAM_CRLFILE,
	/**
	 * @brief Specifies the CA file.
	 */
	ZSTREAM_CAPATH,
	/**
	 * @brief Specifies directory holding CA certificates.
	 */
	ZSTREAM_CAFOLDER
};

/**
 * @brief Starts a new zstream session.
 *
 * This function allocates memory to storing zstream
 * data for a new session. The default HTTP action is a GET action.
 *
 * @retval Pointer to zstream session.
 * @see zstream_clean
 * @see zstream_open
 * @see zstream_close
 */
zstream_t *zstream_init(void);

/**
 * @brief Ends a zstream session.
 *
 * This function closes the zstream session if needed and deallocates
 * zstream session data.
 *
 * @param [in] stream zstream session
 *
 * @see zstream_init
 * @see zstream_close
 * @see zstream_open
 */
void zstream_clean(zstream_t *stream);

/**
 * @brief Opens a HTTP session.
 *
 * This function connects with a server pointed by the URL data but no other
 * action is taken.
 * That implies that a zstream session must be init and the URL must be set
 * before calling this function.
 * If the URL protocol is https and VERIFYPEER option is set then the library
 * downloads CRL file automatically if is pointed by the certificate.
 *
 * @param [in] stream zstream session.
 *
 * @retval 0 If success.
 * @retval -1 If any error.

 * @see zstream_close
 * @see zstream_init
 * @see zstream_clean
 * @see zstream_setopt
 */
int zstream_open(zstream_t *stream);

/**
 * @brief Closes the HTTP session mantaining the zstream session data.
 *
 * @param [in] stream zstream session.
 *
 * @see zstream_open
 */
void zstream_close(zstream_t *stream);

/**
 * @brief Set options for a zstream session.
 *
 * This function sets the different zstream session options that
 * control the session behaviour.
 *
 * @param [in] stream zstream session
 * @param [in] type option according to ::zstream_opts enum
 * @param [in] option value of option type
 */
void zstream_setopt(zstream_t *stream, int type, const char *option);

/**
 * @brief Sets the write function callback
 *
 * This functions sets a function callback that will be used by
 * the ::zstream_perform function which should match the prototype shown above.
 * The callback functions receives a pointer to data to be saved and the size
 * of that data.
 *
 * @param [in] stream zstream session.
 * @param [in] cb pointer to a user write function.

 * @see zstream_perform
 */
void zstream_setwritecb(zstream_t *stream, data_cb_t *cb);

/**
 * @brief Adds a HTTP header
 *
 * @param [in] stream zstream session
 * @param [in] key header key name
 * @param [in] val header key value

 * @retval 0 If success.
 * @retval -1 If any error.

 * @see zstream_flush_headers
 */
int zstream_add_header(zstream_t *stream, const char *key, const char *val);

/**
 * @brief Removes all headers set by user
 *
 * @param [in] stream zstream session
 */
void zstream_flush_headers(zstream_t *stream);

/**
 * @brief Adds a HTTP cookie
 *
 * @param [in] stream zstream session
 * @param [in] cookie HTTP cookie

 * @retval 0 If success.
 * @retval -1 If any error.

 * @see zstream_flush_cookies
 */
int zstream_add_cookie(zstream_t *stream, const char *cookie);

/**
 * @brief Removes all headers set by user
 *
 * @param [in] stream zstream session
 */
void zstream_flush_cookies(zstream_t *stream);

/**
 * @brief Executes the HTTP request and parses the response
 *
 * This function executes the HTTP request according to set options. If the
 * the connection is not opened the function opens it and closes when
 * the response is parsed.
 *
 * @param [in] stream zstream session
 *
 * @retval 0 If success.
 * @retval -1 If any error.
 */
int zstream_perform(zstream_t *stream);

#endif
