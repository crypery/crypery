/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * SSL/TLS wrapper module header
 * 
 * Declares OpenSSL-compatible API types and functions wrapping the built-in
 * TLS implementation. Provides SSL_CTX/SSL types, handshake, I/O, and
 * timeout configuration.
 */

#ifndef SSL_H
#define SSL_H

#include "tls.h"
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SSL_SERVER_RSA_CERT 1
#define SSL_SERVER_RSA_KEY  2

#define SSL_FILETYPE_PEM    1
#define SSL_VERIFY_NONE     0
#define SSL_VERIFY_PEER     1

// Return codes from ssl_read_record() besides byte count.
#define SSL_READ_CLOSED   -2  // peer closed/aborted transport or timeout > handshake "interrupted" (SSL_accept ret = 1)
#define SSL_READ_INVALID  -3  // peer sent non-TLS / invalid record data > real protocol error (SSL_accept ret = -1)

typedef TLSContext SSL_CTX;
typedef TLSContext SSL;

// Create a new SSL context with the given method
SSL_CTX *SSL_CTX_new();
// Free an SSL context
void SSL_CTX_free(SSL_CTX *ctx);

// Load a certificate file into the context
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *filename, int filetype);
// Load a private key file into the context
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *filename, int filetype);
// Verify that the private key matches the certificate
int SSL_CTX_check_private_key(const SSL_CTX *ctx);

// Create a new SSL object from a context
SSL *SSL_new(SSL_CTX *ctx);
// Free an SSL object
void SSL_free(SSL *ssl);

// Attach a socket file descriptor to an SSL object
int SSL_set_fd(SSL *ssl, int socket_fd);
// Set TLS version (1 for TLS 1.2)
int SSL_set_tls_version(SSL *ssl, int tls12);

// Perform server-side SSL handshake
int SSL_accept(SSL *ssl);
// Perform client-side SSL handshake
int SSL_connect(SSL *ssl);

// Write data through the SSL connection
int SSL_write(SSL *ssl, const void *buf, int len);
// Read data through the SSL connection
int SSL_read(SSL *ssl, void *buf, int len);

// Gracefully shut down the SSL connection
int SSL_shutdown(SSL *ssl);
// Check for pending data in the SSL buffer
int SSL_pending(SSL *ssl);

// Get the error code from the last SSL operation
int SSL_get_error(const SSL *ssl, int ret);

// Get the name of the current cipher
const char *tls_cipher_name(const SSL *ssl);

// Destroy the internal TLS context
void tls_destroy_context(void *ctx);

// Set verification mode and callback
int SSL_set_verify(SSL *ssl, int mode, int (*verify_callback)(SSL_CTX *, void **, int));

// Access to internal SSL state (for retry buffer in server.c)
SSLInternal *ssl_get_internal(SSL *ssl);
// Write directly to the underlying socket
int ssl_sock_write(SSL *ssl, const uint8_t *buf, int len);

/*
 * TLS timeouts (ms; 0 = no timeout). Values loaded from config.json.
 * Set the general I/O timeout
 */
int ssl_set_io_timeout(SSL_CTX *ctx, int timeout_ms);
// Set the handshake timeout
int ssl_set_handshake_timeout(SSL_CTX *ctx, int timeout_ms);
// Set the read poll timeout
int ssl_set_read_poll(SSL_CTX *ctx, int timeout_ms);
// Set the flight timeout
int ssl_set_flight_timeout(SSL_CTX *ctx, int timeout_ms);

#define SSL_R_HANDSHAKE_FAILURE 1
#define SSL_R_READ_SYSCALL      2
#define SSL_R_CLOSED_STREAM     3

#ifdef __cplusplus
}
#endif

#endif // SSL_H