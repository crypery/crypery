# crypery

> [Russian version](README_RU.md)

> [China version](README_CN.md)

## Project Overview

**crypery** is a network stack written in pure C/C++, consisting of four modules: a TLS 1.2/1.3 cryptographic library, an OpenSSL-compatible SSL wrapper layer, an HTTPS server, and an HTTPS client.

Key features:

- **All crypto algorithms implemented from scratch** - no external cryptographic libraries. The only optional dependency is zlib for gzip compression (disabled via the `HTTP_NO_GZIP` flag).
- **Portability** - works on Windows (MinGW, Winsock) and Unix-like systems (BSD sockets, pthreads).
- **Full stack**: from low-level cryptography (AES-GCM, RSA, ECDH) to a ready-to-use HTTP server and HTTP client.

## Module Dependency Diagram

```
┌-----------┐       ┌-----------┐
│   url     │       │   http    │
│  client   │       │  server   │
└-----┬-----┘       └-----┬-----┘
      │                   │
      └--------┬----------┘
         ┌-----------┐
         │   ssl     │
         │  wrapper  │
         └-----┬-----┘               
         ┌-----------┐
         │   tls     │
         │  crypto   │
         └-----------┘
```

## Module Descriptions

### tls

The base cryptographic layer. A pure C/C++ implementation of the TLS 1.2 and TLS 1.3 protocols with a built-in set of primitives:

- symmetric encryption AES-128-GCM;
- hashing SHA-256, MAC HMAC-SHA256, key derivation HKDF-SHA256;
- asymmetric cryptography: RSA-2048 (PKCS#1 v1.5 and RSASSA-PSS signatures), ECDH on the P-256 (secp256r1) and X25519 curves;
- generation and parsing of self-signed X.509 certificates (DER/PEM), including loading PEM files;
- TLS connection context: handshake (client/server, automatic version selection), application data encryption and decryption, SNI, peer certificate verification, close_notify;
- thread safety: random number generation (xorshift128) is protected by a lock, allowing parallel handshakes in a thread pool.

### ssl

An OpenSSL-compatible API layer over the built-in TLS implementation. Designed so that code written for OpenSSL works unchanged:

- OpenSSL-compatible context and connection types;
- loading certificates and private keys from PEM files, key-to-certificate match verification;
- server and client handshakes (TLS 1.2/1.3);
- encrypted I/O over a socket;
- configurable timeouts: I/O operation, full handshake, TLS record write wait, fragmented packet assembly;
- peer certificate verification modes;
- platform shim: Winsock on Windows, BSD sockets on POSIX.

### http

A self-contained HTTP/1.1 server library built on the built-in TLS stack:

- request routing by method and path with user-defined handlers;
- static file serving from a root directory with MIME type detection;
- gzip compression: serving pre-compressed `.gz` files and on-the-fly compression via zlib (disabled by `HTTP_NO_GZIP`);
- WebSocket (RFC 6455): connection upgrade, reading and sending frames (text, binary, close, ping/pong);
- Server-Sent Events (SSE);
- query string parsing (URL decoding) and multipart/form-data (including file uploads);
- security: path traversal protection, blocking of sensitive paths (`.git`, `.env`, `config*`, etc.), Host header validation against a domain list, body and header size limits;
- worker thread pool with a ring queue of connections, blocking accept loop;
- automatic TLS/HTTP detection by the first byte (0x16 → TLS, otherwise HTTP with a 426 response);
- statistics: request counters by status code category, uptime, req/s;
- its own platform shim (sockets, strings, threads, mutexes, events) - the module does not depend on external compat headers.

### url

A self-contained HTTP/HTTPS client library built on the built-in TLS stack:

- absolute URL parsing: http/https, explicit port, userinfo, fragments, IPv6 literals;
- performing HTTP/1.1 requests (GET, POST, HEAD, etc.) with custom headers, body, Content-Type, Range;
- response reading: status line, headers, body by Content-Length, chunked transfer encoding, or until EOF;
- redirect handling (301/302/303/307/308) with RFC 7231 method semantics and a redirect count limit;
- multipart/form-data body building (fields and files, boundary generation, MIME detection by extension);
- cookie jar: one in-memory list shared by every `UrlCtx` with optional persistence to a file (`ctx->use_cook` / `ctx->cook_file`); RFC 6265-style matching (Domain/Path, Secure over TLS only, Max-Age/Expires), automatic `Set-Cookie` storage and `Cookie` sending on GET;
- transport layer: DNS resolution, connection with timeout, TLS handshake (SNI, option to skip certificate verification), buffered I/O;
- error codes compatible with curl conventions;
- optional verbose logging via a callback (disabled by `URL_NO_LOG`).

## Main Technologies Used

- **Language**: pure C/C++, no external dependencies (zlib - optional).
- **Protocols**: TLS 1.2, TLS 1.3, HTTP/1.1, HTTPS, WebSocket (RFC 6455), SSE, chunked transfer encoding.
- **Cryptography**: AES-128-GCM, SHA-256, HMAC-SHA256, HKDF-SHA256, RSA-2048 (PKCS#1 v1.5, RSASSA-PSS), ECDH P-256 (secp256r1), X25519, X.509 (DER/PEM), SHA-1 (WebSocket handshake only).
- **Network layer**: Winsock2 (Windows) / BSD sockets (POSIX), `select()` for timeouts, `SO_RCVTIMEO`, `getaddrinfo` for DNS.
- **Threading**: WinAPI threads (Windows) / pthreads (POSIX), worker thread pool, critical sections / mutexes, auto-reset events.
- **Compression**: gzip via zlib (optional).
- **API compatibility**: OpenSSL (SSL_CTX/SSL) and curl (url_*).

## Usage Examples

### tls

Generating a key, a self-signed certificate, and performing a handshake:

```c
#include "tls.h"

/* Generate an RSA-2048 key and a self-signed certificate */
RSAKey key;
tls_rsa_generate_key(&key);

uint8_t cert[TLS_RSA_MAX_CERT_SIZE];
int cert_len = sizeof(cert);
tls_generate_self_signed_cert(&key, cert, &cert_len);

/* Server context with automatic TLS version selection */
TLSContext ctx;
tls_init_context_auto(&ctx, 1);
tls_set_rsa_key(&ctx, &key);
tls_set_certificate(&ctx, cert, cert_len);

/* Step-by-step handshake: feed incoming data, get outgoing data */
uint8_t in[TLS_RSA_MAX_BUFFER], out[TLS_RSA_MAX_BUFFER];
int in_len = 0, out_len = 0;
int ret = tls_handshake_step(&ctx, in, in_len, out, &out_len);
/*... send out and call again with new in until complete... */

/* Encrypted sending and receiving of application data */
uint8_t data[] = "hello";
ret = tls_send_application_data(&ctx, data, sizeof(data) - 1, out, &out_len);

uint8_t plain[TLS_RSA_MAX_BUFFER];
int plain_len = sizeof(plain);
ret = tls_receive_application_data(&ctx, in, in_len, plain, &plain_len);

/* Proper connection close */
tls_close(&ctx, out, &out_len);
```

### ssl

An OpenSSL-compatible server:

```c
#include "ssl.h"

/* Context: load certificate and key from PEM */
SSL_CTX *ctx = SSL_CTX_new();
SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM);
SSL_CTX_check_private_key(ctx);

/* Timeouts (ms) */
ssl_set_io_timeout(ctx, 5000);
ssl_set_handshake_timeout(ctx, 10000);

/* Connection on an accepted socket */
SSL *ssl = SSL_new(ctx);
SSL_set_fd(ssl, socket_fd);

if (SSL_accept(ssl) == 0) {
    char buf[4096];
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n > 0)
        SSL_write(ssl, "OK", 2);
}

SSL_shutdown(ssl);
SSL_free(ssl);
SSL_CTX_free(ctx);
```

The client side is analogous: `SSL_connect()` instead of `SSL_accept()`.

### http

A server with an API route and static file serving:

```c
#include "http.h"

/* Route handler */
int handle_info(http_server_t *http, http_ctx_t *c,
                const char *method, const char *uri,
                const char *body, size_t body_len)
{
    http_send_json_response(http, c, 200, "{\"status\":\"ok\"}");
    return 0;
}

int main(void)
{
    http_server_t *http = http_init();
    http->port = 443;
    http->ssl_use = true;
    http->cert_file = "localhost.crt";
    http->key_file = "localhost.key";

    /* per-domain document roots; hosts not listed are rejected (400) */
    http_domain(http, "localhost", "www");
    http_domain(http, "127.0.0.1", "www");
    http_domain(http, "test.localhost", "test");

    /* routes are domain-scoped: registered only for "localhost" */
    http_route(http, "localhost", "GET", "/api/info", handle_info);

    http_run(http, my_log_cb);   /* NULL - disable module logging */
    http_free(http);
    return 0;
}
```

Requests to paths without registered routes are automatically served by static file serving from the document root of the request's `Host` domain (see `http_domain()`); when no domains are configured every host is served from the built-in default root `DEF_ROOT` (`www`). Routes are registered per domain: `http_route(http, domain, method, path, handler)` applies only to that domain, or to every domain when the domain argument is `NULL`.

### url

Performing an HTTPS request:

```c
#include "url.h"

UrlCtx *ctx = url_init();
ctx->verbose = 1;                          /* verbose console output */
ctx->follow_redirects = 1;                 /* follow redirects */

url_set_header(ctx, "X-Api-Key", "123");   /* custom header */
url_set_data(ctx, "a=1&b=2", 7);           /* POST body */
url_set_content_type(ctx, "application/x-www-form-urlencoded");

char *data = url_run(ctx, "https://example.com", "POST", NULL);
if (data) {
    printf("status: %d\n", url_status(ctx));
    printf("%s", data);
    free(data);                            /* buffer is allocated by url_run() */
} else {
    printf("error: %d\n", ctx->last_error);
}
url_free(ctx);
```

Cookies (shared jar):

```c
#include "url.h"

UrlCtx *ctx = url_init();

/* Enable the cookie jar. Cookies are kept in one shared in-memory list and,
 * because cook_file is set, loaded from "cookies.txt" on the first url_run()
 * (if the file exists) and saved back to it on every Set-Cookie - so the next
 * application run starts with the saved cookies.
 * ctx->cook_file = NULL would keep the list in memory only. */
ctx->use_cook  = true;
ctx->cook_file = "cookies.txt";

char *data = url_run(ctx, "https://example.com/login", "GET", NULL);
if (data) {
    /* The server answered with "Set-Cookie: sid=abc; Path=/" - the cookie
     * is now stored in the shared jar and written to cookies.txt. */
    free(data);
}

/* The next request automatically carries "Cookie: sid=abc" (GET only) */
data = url_run(ctx, "https://example.com/profile", "GET", NULL);
if (data) {
    printf("%s", data);
    free(data);
}
url_free(ctx);
```

The jar is a single list shared by every `UrlCtx`; entries are matched per RFC 6265 basics (Domain/Path attributes, Secure only over TLS, Max-Age/Expires). `url_cookie_header_for()`, `url_cookie_set_from_url()`, `url_cookie_load()` and `url_cookie_save()` are available for direct access to the list.

## License

GNU AGPL v3 (Affero GPL)
