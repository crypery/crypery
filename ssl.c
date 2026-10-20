/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * SSL/TLS wrapper module
 *
 * OpenSSL-compatible API layer over the built-in TLS implementation (tls).
 * Manages SSL contexts, connections, handshakes, and encrypted I/O with
 * configurable timeouts using select().
 *
 * Portability: uses Winsock on Windows (#ifdef _WIN32) and BSD sockets on
 * POSIX systems. All platform-specific bits are isolated in the portability
 * shim at the top of the file (socket types, error codes, sleeps, tick
 * counter).
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "ssl.h"
#include "tls.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

// ---- portability shims: Winsock on Windows, BSD sockets on POSIX ----
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#define socklen_t int
#define net_err()      WSAGetLastError()
#define NET_CONNABORTED WSAECONNABORTED
#define NET_CONNRESET   WSAECONNRESET
#define NET_NETRESET    WSAENETRESET
#define NET_NOTCONN     WSAENOTCONN
#define NET_WOULDBLOCK  WSAEWOULDBLOCK
#define NET_TIMEDOUT    WSAETIMEDOUT
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#define SOCKET         int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define net_err()      errno
#define NET_CONNABORTED ECONNABORTED
#define NET_CONNRESET   ECONNRESET
#if defined(ENETRESET)
#define NET_NETRESET    ENETRESET
#else
#define NET_NETRESET    ECONNRESET
#endif
#define NET_NOTCONN     ENOTCONN
#define NET_WOULDBLOCK  EAGAIN
#define NET_TIMEDOUT    EAGAIN
#define closesocket    close
#define ioctlsocket    ioctl
#define SD_BOTH        SHUT_RDWR
#endif

// Portable millisecond sleep (Sleep on Windows, nanosleep on POSIX)
static void net_sleep(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

// Portable monotonically increasing tick counter in milliseconds
static unsigned net_tick(void) {
#ifdef _WIN32
    return (unsigned)GetTickCount();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
#endif
}

// Declaration of helper function r16 from tls.c
static uint16_t r16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }

// Forward-declared functions
static int ssl_wait_read(SSLInternal *si, int timeout_ms);
static int ssl_wait_write(SSLInternal *si, int timeout_ms);

// Per-connection internal state - embedded in TLSContext (see tls.h)
/* Timeouts (io/handshake/read_poll/flight) are stored per SSL_CTX and
 * copied into each SSL connection (see SSL_CTX_new / SSL_new). */

// Forward-declared functions
static int ssl_do_handshake(SSL *ssl);

// Destroy TLS context internals
void tls_destroy_context(void *ctx) {
    (void)ctx;
    // Connection state is owned by SSL_free / SSL_CTX_free below.
}

// Get internal SSL state
SSLInternal *ssl_get_internal(SSL *ssl) {
    if (!ssl) return NULL;
    return &((TLSContext*)ssl)->io;
}

/* Create SSL context with default timeouts (ms; 0 = no timeout).
 * Timeouts can be adjusted later via ssl_set_*_timeout(). */
SSL_CTX *SSL_CTX_new() {
    TLSContext *ctx = (TLSContext*)calloc(1, sizeof(TLSContext));
    if (ctx) {
      tls_init_context(ctx, 1, TLS_VERSION_AUTO);
      ctx->tls13 = 0; // negotiate TLS 1.2 / 1.3 per connection
      ctx->io_timeout = 5000;
      ctx->handshake_timeout = 10000;
      ctx->read_poll = 500;
      ctx->flight_timeout = 5000;
    }
    return (SSL_CTX*)ctx;
}

// Set I/O operation timeout
int ssl_set_io_timeout(SSL_CTX *ctx, int timeout_ms) {
    if (!ctx) return -1;
    if (timeout_ms < 0) timeout_ms = 0;            // 0 = no timeout (wait forever)
    if (timeout_ms > 60000) timeout_ms = 60000;
    ((TLSContext*)ctx)->io_timeout = timeout_ms;
    return ((TLSContext*)ctx)->io_timeout;
}

// Set handshake timeout
int ssl_set_handshake_timeout(SSL_CTX *ctx, int timeout_ms) {
    if (!ctx) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    if (timeout_ms > 120000) timeout_ms = 120000;
    ((TLSContext*)ctx)->handshake_timeout = timeout_ms;
    return ((TLSContext*)ctx)->handshake_timeout;
}

// Set TLS record poll timeout
int ssl_set_read_poll(SSL_CTX *ctx, int timeout_ms) {
    if (!ctx) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    if (timeout_ms > 60000) timeout_ms = 60000;
    ((TLSContext*)ctx)->read_poll = timeout_ms;
    return ((TLSContext*)ctx)->read_poll;
}

// Set flight assembly timeout
int ssl_set_flight_timeout(SSL_CTX *ctx, int timeout_ms) {
    if (!ctx) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    if (timeout_ms > 60000) timeout_ms = 60000;
    ((TLSContext*)ctx)->flight_timeout = timeout_ms;
    return ((TLSContext*)ctx)->flight_timeout;
}

// Free SSL context
void SSL_CTX_free(SSL_CTX *ctx) {
    if (!ctx) return;
    tls_destroy_context(ctx);
    free(ctx);
}

// Load certificate from PEM file (leaf + optional chain).
// A Let's Encrypt fullchain file holds leaf + R10/R11 intermediate.
// Old code loaded only the first block, so Chrome saw an incomplete
// chain (ERR_CERT_AUTHORITY_INVALID). Now all blocks are loaded.
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *filename, int filetype) {
    (void)filetype;
    if (!ctx || !filename) return -1;
    TLSContext *tctx = (TLSContext*)ctx;
    uint8_t leaf[TLS_RSA_MAX_CERT_SIZE];
    uint8_t chain[TLS_RSA_MAX_CHAIN_SIZE];
    int leaf_len = 0, chain_len = 0;
    if (tls_pem_to_chain_der(filename, leaf, &leaf_len, (int)sizeof(leaf),
                             chain, &chain_len, (int)sizeof(chain)) != 0) {
        // Fallback for single-block PEM files.
        uint8_t der[TLS_RSA_MAX_CERT_SIZE];
        int der_len = sizeof(der);
        if (tls_pem_to_der(filename, der, &der_len, sizeof(der)) != 0) return -1;
        return tls_set_certificate(tctx, der, der_len);
    }
    if (tls_set_certificate(tctx, leaf, leaf_len) != 0) return -1;
    if (chain_len > 0 && tls_set_chain(tctx, chain, chain_len) != 0) return -1;
    return 0;
}

// Load private key from PEM file
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *filename, int filetype) {
    (void)filetype;
    if (!ctx || !filename) return -1;
    TLSContext *tctx = (TLSContext*)ctx;
    uint8_t der[4096];
    int der_len = sizeof(der);
    if (tls_pem_to_der(filename, der, &der_len, sizeof(der)) != 0) return -1;
    RSAKey *key = &tctx->static_rsa_key;
    if (tls_rsa_parse_private_der(key, der, der_len) != 0) return -1;
    tctx->has_rsa_key = 1;
    return 0;
}

// Verify key matches certificate
int SSL_CTX_check_private_key(const SSL_CTX *ctx) {
    if (!ctx) return 0;
    const TLSContext *tctx = (const TLSContext*)ctx;
    if (!tctx->has_rsa_key) return 0;
    if (!tctx->has_cert) return 0;

    // Check: sign test hash with private key, verify with public key
    RSAKey pub_key;
    memset(&pub_key, 0, sizeof(pub_key));
    if (tls_rsa_parse_public_der(&pub_key, tctx->cert, tctx->cert_len) != 0) return 0;
    
    uint8_t test_hash[32];
    memset(test_hash, 0x42, sizeof(test_hash));
    
    uint8_t sig[TLS_RSA_SIGNATURE_LEN];
    int sig_len = 0;
    if (tls_rsa_sign(&tctx->static_rsa_key, test_hash, sig, &sig_len) != 0) return 0;
    
    return tls_rsa_verify(&pub_key, test_hash, sig, sig_len) == 0 ? 1 : 0;
}

// Create SSL connection from context
SSL *SSL_new(SSL_CTX *ctx) {
    if (!ctx) return NULL;
    TLSContext *tctx = (TLSContext*)calloc(1, sizeof(TLSContext));
    if (!tctx) return NULL;

    // Copy certificate and key from context
    const TLSContext *src = (const TLSContext*)ctx;
    tls_init_context(tctx, src->is_server, TLS_VERSION_AUTO);

    if (src->has_cert && src->cert_len > 0) {
        tls_set_certificate(tctx, src->cert, src->cert_len);
    }
    if (src->chain_len > 0) {
        tls_set_chain(tctx, src->chain, src->chain_len);
    }
    if (src->has_rsa_key) {
        memcpy(&tctx->static_rsa_key, &src->static_rsa_key, sizeof(RSAKey));
        tctx->has_rsa_key = 1;
    }

    // Copy timeout settings from the context
    tctx->io_timeout = src->io_timeout;
    tctx->handshake_timeout = src->handshake_timeout;
    tctx->read_poll = src->read_poll;
    tctx->flight_timeout = src->flight_timeout;

    tctx->io.socket_fd = -1;
    
    return (SSL*)tctx;
}

// Free SSL connection
void SSL_free(SSL *ssl) {
    if (!ssl) return;
    TLSContext *tctx = (TLSContext *)ssl;
    (void)tctx;
    tls_destroy_context(ssl);
    free(ssl);
}

// Set TLS version preference
int SSL_set_tls_version(SSL *ssl, int tls13) {
    if (!ssl) return -1;
    TLSContext *ctx = (TLSContext*)ssl;
    ctx->tls13 = tls13 ? 1 : 0;
    return 0;
}

// Attach socket to SSL connection
int SSL_set_fd(SSL *ssl, int socket_fd) {
    if (!ssl) return -1;
    SSLInternal *si = ssl_get_internal(ssl);
    si->socket_fd = socket_fd;
    si->fd_set = 1;
    si->rw_error = 0;
    return 0;
}

/* Wait for read readiness up to timeout_ms (0 = no timeout → block until
 * ready). select() is used here only as a timer - socket remains in
 * blocking mode. */
static int ssl_wait_read(SSLInternal *si, int timeout_ms) {
    if (!si || si->socket_fd < 0) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET((SOCKET)si->socket_fd, &rd);
    if (timeout_ms == 0) return select((int)si->socket_fd + 1, &rd, NULL, NULL, NULL);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select((int)si->socket_fd + 1, &rd, NULL, NULL, &tv);
}

// Wait for write readiness up to timeout_ms (only for timeouts).
static int ssl_wait_write(SSLInternal *si, int timeout_ms) {
    if (!si || si->socket_fd < 0) return -1;
    if (timeout_ms < 0) timeout_ms = 0;
    fd_set wr;
    FD_ZERO(&wr);
    FD_SET((SOCKET)si->socket_fd, &wr);
    if (timeout_ms == 0) return select((int)si->socket_fd + 1, NULL, &wr, NULL, NULL);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select((int)si->socket_fd + 1, NULL, &wr, NULL, &tv);
}

/* Blocking read from socket: thread blocks until data received,
 * connection closed (return 0), or I/O timeout expired (-1).
 *
 * Uses the socket's SO_RCVTIMEO directly via recv() instead of
 * select()+recv(). The select() gate was buggy: when select()
 * timed out (returned 0), ssl_sock_read returned -1 WITHOUT calling
 * recv(), causing SSL_read to retry - each retry waited the full
 * io_timeout again (4×10s = 40s dead wait).
 *
 * SO_RCVTIMEO is set in connect_to_host() and provides reliable
 * per-operation timeout without the select race condition. */
static int ssl_sock_read(SSL *ssl, uint8_t *buf, int len) {
    SSLInternal *si = ssl_get_internal(ssl);
    if (!si || si->socket_fd < 0) return -1;

    // First merge pre-buffered data from retry loop
    if (si->prebuf_len > 0) {
        int to_copy = len < si->prebuf_len ? len : si->prebuf_len;
        memcpy(buf, si->prebuf, (size_t)to_copy);
        si->prebuf_len -= to_copy;
        if (si->prebuf_len > 0) {
            memmove(si->prebuf, si->prebuf + to_copy, (size_t)si->prebuf_len);
        }
        return to_copy;
    }

    int n = (int)recv(si->socket_fd, (char *)buf, (size_t)len, 0);
    if (n == SOCKET_ERROR) {
        int err = net_err();
        /* Transport break in the middle of handshake (Chrome cancels
         * speculative connections with RST) - this is normal client disconnect,
         * not a TLS failure: report the same as a clean close. */
        if (err == NET_CONNABORTED || err == NET_CONNRESET ||
            err == NET_NETRESET || err == NET_NOTCONN) {
            si->closed = 1;
            return 0;
        }
        if (err == NET_WOULDBLOCK || err == NET_TIMEDOUT) {
            /* Transient: recv() can return WOULDBLOCK even with SO_RCVTIMEO
             * set (e.g. socket in pending-error state). Retry once with a
             * short sleep. */
            net_sleep(5);
            n = (int)recv(si->socket_fd, (char *)buf, (size_t)len, 0);
            if (n == SOCKET_ERROR) {
                err = net_err();
                if (err != NET_WOULDBLOCK && err != NET_TIMEDOUT) {
                    si->rw_error = 1;
                }
                return -1;
            }
        } else {
            si->rw_error = 1;
            return -1;
        }
    }
    if (n == 0) si->closed = 1;
    return n;
}

/*
 * Blocking write: blocks until entire buffer is written (or timeout).
 * Write raw bytes to socket
 */
int ssl_sock_write(SSL *ssl, const uint8_t *buf, int len) {
    SSLInternal *si = ssl_get_internal(ssl);
    if (!si || si->socket_fd < 0) return -1;
    int total = 0;
    while (total < len) {
        if (ssl_wait_write(si, ((TLSContext*)ssl)->io_timeout) <= 0) return total > 0 ? total : -1;
        int n = (int)send(si->socket_fd, (const char *)(buf + total), (size_t)(len - total), 0);
        if (n == SOCKET_ERROR) {
            int err = net_err();
            if (err == NET_WOULDBLOCK || err == NET_TIMEDOUT) continue;
            si->rw_error = 1;
            return total > 0 ? total : -1;
        }
        if (n == 0) return total > 0 ? total : -1;
        total += n;
    }
    return total;
}


/* Read a complete TLS record (5-byte header + payload) into buf.
 * Returns bytes read (>0; may be partial if peer leaves),
 * SSL_READ_CLOSED on disconnect/timeout, SSL_READ_INVALID on invalid data. */
static int ssl_read_record(SSL *ssl, uint8_t *buf, int max_len) {
    SSLInternal *si = ssl_get_internal(ssl);
    if (!si) return SSL_READ_CLOSED;

    int have = 0;
    for (;;) {
        if (have < 5) {
            /* ssl_sock_read() already waits for I/O timeout, so
             * quietly connected peer is served quickly - without extra wait. */
            int n = ssl_sock_read(ssl, buf + have, 5 - have);
            if (n <= 0) {
                if (have > 0) break; // partial header - let caller handle
                return SSL_READ_CLOSED;
            }
            have += n;
            continue;
        }
        // Strict record type check: must be 0x14-0x17 (TLS record types)
        uint8_t rec_type = buf[0];
        if (rec_type < 0x14 || rec_type > 0x17) {
            return SSL_READ_INVALID; // non-TLS / garbage on TLS port
        }
        // TLS version check: must be 3.0-3.4
        uint16_t rec_version = (uint16_t)((buf[1] << 8) | buf[2]);
        if (rec_version < 0x0301 || rec_version > 0x0304) {
            return SSL_READ_INVALID; // invalid TLS version
        }
        uint16_t rec_len = (uint16_t)((buf[3] << 8) | buf[4]);
        // Record length check: max 16384 bytes per RFC 5246
        if (rec_len > 16384) {
            return SSL_READ_INVALID; // record too large
        }
        int need = 5 + (int)rec_len;
        if (have >= need) break;
        if (have >= max_len) break;
        int n = ssl_sock_read(ssl, buf + have, need - have);
        if (n <= 0) {
            if (have >= need) break;
            return have > 0 ? have : SSL_READ_CLOSED;
        }
        have += n;
    }
    return have;
}

/* Drain remaining TLS records already waiting in socket.
 * Appends to buf via *len (up to max). Used to collect complete packets
 * sent across multiple sequential records. */
static int ssl_drain_more(SSL *ssl, uint8_t *buf, int *len, int max) {
    SSLInternal *si = ssl_get_internal(ssl);
    if (!si) return -1;
    int total = 0;
    for (;;) {
#ifdef _WIN32
        u_long avail = 0;
        if (ioctlsocket((SOCKET)si->socket_fd, FIONREAD, &avail) != 0) break;
#else
        int avail = 0;
        if (ioctl(si->socket_fd, FIONREAD, &avail) != 0) break;
#endif
        if (avail == 0) break;
        int chunk = (int)avail;
        if (*len + chunk > max) chunk = max - *len;
        if (chunk <= 0) break;
        int n = (int)recv((SOCKET)si->socket_fd, (char*)(buf + *len), (size_t)chunk, 0);
        if (n <= 0) { n = (int)recv((SOCKET)si->socket_fd, (char*)(buf + *len), (size_t)chunk, 0); if (n <= 0) { si->closed = 1; break; } }
        *len += n;
        total += n;
        if (*len >= max) break;
    }
    return total;
}

/* Perform full TLS 1.2/1.3 handshake. Blocking: iteratively calls
 * tls_handshake_step, feeding complete record packets.
 * Returns 0 on success, 1 if peer disconnected before handshake
 * completion (timeout / close / RST - normal for browsers canceling
 * speculative connections), -1 on real TLS protocol error (invalid
 * or non-TLS data from peer, bad handshake state). */
static int ssl_do_handshake(SSL *ssl) {
    TLSContext *ctx = (TLSContext*)ssl;
    SSLInternal *si = ssl_get_internal(ssl);
    if (!si) return -1;

    if (ctx->handshake_done) return 0;

    uint8_t in[TLS_RSA_MAX_BUFFER];
    int in_len = 0;
    uint8_t out[TLS_RSA_MAX_BUFFER];
    int out_len;
    int ret;

    // summary handshake timeout (config timeout_handshake; 0 = no limit).
    unsigned handshake_start = net_tick();

    // Client: first create and send ClientHello (no input needed).
    if (!ctx->is_server) {
        ret = tls_handshake_step(ctx, NULL, 0, out, &out_len);
        if (ret == TLS_RSA_ERROR) return -1;
        if (out_len > 0) {
            int total_sent = 0;
            while (total_sent < out_len) {
                int n = ssl_sock_write(ssl, out + total_sent, out_len - total_sent);
                if (n <= 0) return -1;
                total_sent += n;
            }
        }
        if (ctx->handshake_done) return 0;
    }

    for (;;) {
        // Check summary handshake timeout
        if (ctx->handshake_timeout > 0 &&
            net_tick() - handshake_start > (unsigned)ctx->handshake_timeout) {
            return 1;
        }

        // Read a complete TLS record packet.
        in_len = ssl_read_record(ssl, in, (int)sizeof(in));
        if (in_len == SSL_READ_INVALID) {
            /* Peer sent non-TLS / invalid data on TLS port: this is
             * a real protocol violation, not a canceled connection. */
            return -1;
        }
        if (in_len <= 0) {
            /* Peer closed/aborted or timeout in the middle of handshake: worker
             * simply drops the connection; this is not a TLS failure. */
            return 1;
        }

        ssl_drain_more(ssl, in, &in_len, (int)sizeof(in));

        ret = tls_handshake_step(ctx, in, in_len, out, &out_len);
        if (ret == TLS_RSA_ERROR && ctx->is_server && !ctx->handshake_done) {
            // Check if client sent Application Data directly (TLS 1.3 fallback)
            int offset = 0;
            while (in_len >= offset + 6 && in[offset] == TLS_RSA_CHANGE_CIPHER &&
                   r16(in + offset + 3) == 1) {
                offset += 5 + (int)r16(in + offset + 3);
            }
            if (in_len >= offset + 5 && in[offset] == TLS_RSA_APPLICATION_DATA) {
                uint16_t app_rec_len = r16(in + offset + 3);
                if (in_len >= offset + 5 + (int)app_rec_len) {
                    uint8_t decrypted[8192]; int dec_len;
                    if (decrypt_record(ctx, in + offset, 5 + (int)app_rec_len, decrypted, &dec_len) == 0) {
                        // Check nested TLS record (encrypted TLS 1.3 handshake inside Application Data)
                        if (dec_len >= 5 && decrypted[0] >= 0x14 && decrypted[0] <= 0x17) {
                            uint16_t inner_rec_len = r16(decrypted + 3);
                            if (dec_len >= 5 + (int)inner_rec_len) {
                                uint8_t inner_decrypted[8192]; int inner_dec_len;
                                if (decrypt_record(ctx, decrypted, 5 + (int)inner_rec_len, inner_decrypted, &inner_dec_len) == 0) {
                                    if (inner_dec_len > 0 && inner_dec_len < (int)sizeof(ctx->recv_buffer.data)) {
                                        memcpy(ctx->recv_buffer.data, inner_decrypted, (size_t)inner_dec_len);
                                        ctx->recv_buffer.len = (uint32_t)inner_dec_len;
                                    }
                                    ctx->handshake_done = 1;
                                    return 0;
                                }
                            }
                        }
                        if (dec_len > 0 && dec_len < (int)sizeof(ctx->recv_buffer.data)) {
                            memcpy(ctx->recv_buffer.data, decrypted, (size_t)dec_len);
                            ctx->recv_buffer.len = (uint32_t)dec_len;
                        }
                        ctx->handshake_done = 1;
                        return 0;
                    }
                }
            }
            return -1;
        }
        if (ret == TLS_RSA_ERROR) {
            return -1;
        }
        if (ret == TLS_RSA_NEED_MORE_DATA) {
            // Feed remaining packet data if split across reads
            unsigned loop_start = net_tick();
            for (int i = 0; i < 40 && ret == TLS_RSA_NEED_MORE_DATA; i++) {
                if (ctx->flight_timeout > 0 &&
                    net_tick() - loop_start > (unsigned)ctx->flight_timeout) { break; }
                if (ssl_wait_read(si, ctx->read_poll) > 0) {
                    ssl_drain_more(ssl, in, &in_len, (int)sizeof(in));
                }
                if (si->closed && !si->rw_error) return 1;
                ret = tls_handshake_step(ctx, in, in_len, out, &out_len);
            }
            if (ret == TLS_RSA_NEED_MORE_DATA) {
                /* Client stopped in the middle of packet (or closed); treat as
                 * simple disconnect, not a TLS protocol failure. */
                return 1;
            }
        }

        if (out_len > 0) {
            int total_sent = 0;
            while (total_sent < out_len) {
                int n = ssl_sock_write(ssl, out + total_sent, out_len - total_sent);
                if (n <= 0) return 1; // peer left while we were responding
                total_sent += n;
            }
        }

        if (ctx->handshake_done) return 0;
        if (ret == TLS_RSA_HANDSHAKE_DONE) continue;
    }

    return ctx->handshake_done ? 0 : -1;
}

// Perform TLS handshake as server
int SSL_accept(SSL *ssl) {
    if (!ssl) return -1;
    TLSContext *ctx = (TLSContext*)ssl;

    // Initialize as server only on first call
    if (!ctx->is_server) {
      SSLInternal io = ctx->io;
      int t_io = ctx->io_timeout;
      int t_hs = ctx->handshake_timeout;
      int t_rp = ctx->read_poll;
      int t_fl = ctx->flight_timeout;
      tls_init_context(ctx, 1, ctx->tls13 ? 1 : 0);
      ctx->io = io;
      ctx->io_timeout = t_io;
      ctx->handshake_timeout = t_hs;
      ctx->read_poll = t_rp;
      ctx->flight_timeout = t_fl;
      ctx->tls13 = 0;
    }

    int ret = ssl_do_handshake(ssl);
    return ret;
}

// Perform TLS handshake as client
int SSL_connect(SSL *ssl) {
    if (!ssl) return -1;
    TLSContext *ctx = (TLSContext*)ssl;

    // Initialize as client if not already initialized
    if (ctx->is_server) {
        /* tls_init_context() zeroes the context, so preserve fields
         * that the caller set before the handshake driver took over. */
        SSLInternal io = ctx->io;
        int t_io = ctx->io_timeout;
        int t_hs = ctx->handshake_timeout;
        int t_rp = ctx->read_poll;
        int t_fl = ctx->flight_timeout;
        uint8_t sn[256];
        int sn_len = ctx->server_name_len;
        if (sn_len > 0 && sn_len <= (int)sizeof(sn)) memcpy(sn, ctx->server_name, (size_t)sn_len);
        int sn_saved = (sn_len > 0 && sn_len <= (int)sizeof(sn));
        int ver = (ctx->tls13 == TLS_RSA_VERSION_AUTO) ? TLS_VERSION_AUTO :
                  (ctx->tls13 ? TLS_VERSION_13 : TLS_VERSION_12);
        tls_init_context(ctx, 0, ver);
        ctx->io = io;
        ctx->io_timeout = t_io;
        ctx->handshake_timeout = t_hs;
        ctx->read_poll = t_rp;
        ctx->flight_timeout = t_fl;
        if (sn_saved) {
            ctx->server_name_len = sn_len;
            memcpy(ctx->server_name, sn, (size_t)sn_len);
        }
    }
    
    return ssl_do_handshake(ssl);
}

// Write encrypted data
int SSL_write(SSL *ssl, const void *buf, int len) {
    if (!ssl || !buf || len <= 0) return -1;
    TLSContext *ctx = (TLSContext*)ssl;

    if (!tls_is_established(ctx)) {
        int ret = ssl_do_handshake(ssl);
        if (ret != 0) return -1;
    }

    // Check if this is already a TLS record (starts with type 0x14-0x17)
    const uint8_t *data = (const uint8_t*)buf;
    if (len >= 5 && data[0] >= 0x14 && data[0] <= 0x17) {
        // Already a TLS record - send directly
        int total_sent = 0;
        while (total_sent < len) {
            int n = ssl_sock_write(ssl, data + total_sent, len - total_sent);
            if (n <= 0) return total_sent > 0 ? total_sent : -1;
            total_sent += n;
        }
        return total_sent;
    }
    
    // A single TLS record must fit in TLS_RSA_MAX_BUFFER bytes:
    //   TLS 1.2: 5 (hdr) + 8 (IV) + pt + 16 (tag)
    //   TLS 1.3: 5 (hdr) + pt + 1 (inner type) + 16 (tag)
    // Split the payload into chunks that fit one record so large writes
    // (e.g. static files > 16 KB) are sent as multiple records.
    int max_chunk = TLS_RSA_MAX_BUFFER - 29;
    if (max_chunk < 1) max_chunk = 1;
    uint8_t out[TLS_RSA_MAX_BUFFER];
    int total_sent = 0;
    while (total_sent < len) {
        int chunk = len - total_sent;
        if (chunk > max_chunk) chunk = max_chunk;
        int out_len;
        int ret = tls_send_application_data(ctx, data + total_sent, chunk, out, &out_len);
        if (ret != TLS_RSA_OK) return -1;
        int sent = 0;
        while (sent < out_len) {
            int n = ssl_sock_write(ssl, out + sent, out_len - sent);
            if (n <= 0) return -1;
            sent += n;
        }
        total_sent += chunk;
    }

    return len;
}

// Read and decrypt data
int SSL_read(SSL *ssl, void *buf, int len) {
    if (!ssl || !buf || len <= 0) return -1;
    TLSContext *ctx = (TLSContext*)ssl;

    // First deliver any plaintext buffered from previous large record.
    if (ctx->recv_buffer.len > 0) {
        int to_copy = len < (int)ctx->recv_buffer.len ? len : (int)ctx->recv_buffer.len;
        memcpy(buf, ctx->recv_buffer.data, (size_t)to_copy);
        ctx->recv_buffer.len -= to_copy;
        if (ctx->recv_buffer.len > 0) {
            memmove(ctx->recv_buffer.data, 
                    ctx->recv_buffer.data + to_copy, 
                    ctx->recv_buffer.len);
        }
        return to_copy;
    }
uint8_t sock_buf[TLS_RSA_MAX_BUFFER];
    int decrypt_failures = 0;
    int max_decrypt_failures = 5;
    /* Track total time to avoid waiting forever when ssl_sock_read
     * times out on each iteration (100 × 20s = 33 minutes worst case). */
    unsigned start_time = net_tick();
    for (int attempt = 0; attempt < 100; attempt++) {
        // Check summary I/O timeout
        if (ctx->io_timeout > 0 &&
            net_tick() - start_time > (unsigned)ctx->io_timeout) {
            return -1;
        }
        /* If we already hold unprocessed raw TLS records in the recv_raw
         * cache, try to decrypt them first. This is required: ssl_sock_read()
         * reads straight from the socket, which may already be fully drained
         * (peer closed), while complete records still sit in recv_raw. Without
         * this, cached bytes are silently dropped and the read appears truncated. */
        if (ctx->recv_raw.len > 0) {
            uint8_t app_data[TLS_RSA_MAX_BUFFER];
            int data_len;
            int ret = tls_receive_application_data(ctx, NULL, 0, app_data, &data_len);
            if (ret == TLS_RSA_OK && data_len > 0) {
                int to_copy = len < data_len ? len : data_len;
                memcpy(buf, app_data, (size_t)to_copy);
                if (data_len > to_copy) {
                    int remaining = data_len - to_copy;
                    ctx->recv_buffer.len = (uint32_t)remaining;
                    memcpy(ctx->recv_buffer.data, app_data + to_copy, (size_t)remaining);
                }
                return to_copy;
            }
            if (ret == TLS_RSA_CLOSED) return 0; // peer sent close_notify
            if (ret == TLS_RSA_ERROR) return -1;
            /* NEED_MORE_DATA: recv_raw was consumed (partial record cached
             * back); fall through and read more from the socket. */
        }
        /* Always read more from socket; tls_receive_application_data()
         * prepends any incomplete record from ctx->recv_raw cache. */
        int n = ssl_sock_read(ssl, sock_buf, (int)sizeof(sock_buf));
        if (n <= 0) {
            if (n == 0) {
                /* connection closed. Any complete cached raw record was already
                 * delivered by the recv_raw handling above; if recv_raw still
                 * holds data it is an incomplete record that the closed socket
                 * can never complete, so this is genuine EOF. */
                return ctx->recv_buffer.len > 0 ? 1 : 0;
            }
            /* ssl_sock_read returned -1 (timeout or transient error).
             * ssl_sock_read already has its own retry loop for transient
             * WSAEWOULDBLOCK/WSAETIMEDOUT errors, so no need to retry here. */
            return -1;
        }

        uint8_t app_data[TLS_RSA_MAX_BUFFER];
        int data_len;
        int ret = tls_receive_application_data(ctx, sock_buf, n, app_data, &data_len);

        if (ret == TLS_RSA_OK && data_len > 0) {
            decrypt_failures = 0;
            int to_copy = len < data_len ? len : data_len;
            memcpy(buf, app_data, (size_t)to_copy);
            // Save remaining plaintext to buffer
            if (data_len > to_copy) {
                int remaining = data_len - to_copy;
                ctx->recv_buffer.len = (uint32_t)remaining;
                memcpy(ctx->recv_buffer.data, app_data + to_copy, (size_t)remaining);
            }
            return to_copy;
        }
        
        if (ret == TLS_RSA_CLOSED) return 0; // peer sent close_notify
        
        if (ret != TLS_RSA_NEED_MORE_DATA) {
            decrypt_failures++;
            if (decrypt_failures >= max_decrypt_failures) {
                return -1;
            }
        }
        // Need more data - continue reading
        if (ret == TLS_RSA_NEED_MORE_DATA) continue;
        
        return -1;
    }
    
    return 0;
}

// Send TLS close_notify
int SSL_shutdown(SSL *ssl) {
    if (!ssl) return -1;
    TLSContext *ctx = (TLSContext*)ssl;
    
    uint8_t out[64];
    int out_len;
    tls_close(ctx, out, &out_len);
    
    if (out_len > 0) {
        int total_sent = 0;
        while (total_sent < out_len) {
            int n = ssl_sock_write(ssl, out + total_sent, out_len - total_sent);
            if (n <= 0) break;
            total_sent += n;
        }
    }
    
    return 0;
}

// Check pending decrypted bytes
int SSL_pending(SSL *ssl) {
    if (!ssl) return 0;
    TLSContext *ctx = (TLSContext*)ssl;
    return (int)ctx->recv_buffer.len;
}

// Get last error code
int SSL_get_error(const SSL *ssl, int ret) {
    if (ret == 1) return 0;
    if (ret == TLS_RSA_CLOSED) return SSL_R_CLOSED_STREAM;
    if (!tls_is_established((TLSContext*)ssl)) return SSL_R_HANDSHAKE_FAILURE;
    return SSL_R_READ_SYSCALL;
}

// Get cipher suite name
const char *tls_cipher_name(const SSL *ssl) {
    if (!ssl) return "unknown";
    TLSContext *ctx = (TLSContext*)ssl;
    switch (ctx->cipher_suite) {
        case TLS_RSA_CIPHER_SUITE:
            return "ECDHE-RSA-AES128-GCM-SHA256";
        case TLS13_CIPHER_SUITE:
            return "TLS_AES_128_GCM_SHA256";
        default:
            return "unknown";
    }
}

// Set peer verification mode
int SSL_set_verify(SSL *ssl, int mode, int (*verify_callback)(SSL_CTX *, void **, int)) {
    (void)verify_callback;
    if (!ssl) return -1;
    tls_set_peer_verify((TLSContext*)ssl, mode != SSL_VERIFY_NONE);
    return 0;
}
