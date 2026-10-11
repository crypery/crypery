/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * HTTP server module.
 *
 * HTTP/1.1 server with routing, static file serving, gzip compression,
 * WebSocket, SSE, query/multipart parsing, security checks, thread pool, and
 * a blocking I/O accept loop over plain TCP or TLS-wrapped sockets.
 *
 * Example:
 *   http_server_t *http = http_init();
 *   http->port = 443;
 *   http_route(http, "GET", "/api/info", handle_info);
 *   http_run(http, my_log_cb);   pass NULL to silence module logging
 *   http_free(http);
 */

#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>

// Paths and name patterns that are never served to clients
static const char *http_blocked_paths[] = {
    ".svn", ".env", ".git", "*.htaccess", "config*", "wp-admin", "phpmyadmin",
};

// RFC 6455 GUID appended to the Sec-WebSocket-Key during the handshake
static const char *http_ws_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Hard safety cap for request bodies when max_body_mb is 0 (unlimited)
#define HTTP_HARD_MAX_BODY (256 * 1024 * 1024)

// SHA-1 working state (5 x 32-bit words)
typedef struct { uint32_t h[5]; } http_sha1_ctx_t;

// Find a substring in a buffer (memmem equivalent)
static const char *http_memmem(const void *haystack, size_t hlen, const char *needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp((const char *)haystack + i, needle, nlen) == 0)
            return (const char *)haystack + i;
    }
    return NULL;
}

// Effective Server header value for a connection.
static const char *http_srv_name(const http_ctx_t *c) {
    return (c && c->server_name && c->server_name[0]) ? c->server_name : DEF_SERVER_NAME;
}

// Forward declaration: raw send helper defined below (used by www redirect).
static void resp_send(http_ctx_t *c, const void *data, size_t len);
static void http_date_gmt(char *buf, size_t n);

/* Check whether a Host header value matches one of the comma-separated allowed
 * domains. Ports and surrounding whitespace are ignored; comparison is
 * case-insensitive. */
static int http_host_allowed(const char *host, size_t hlen, const char *domains) {
    char hb[512];
    size_t n = hlen < sizeof(hb) - 1 ? hlen : sizeof(hb) - 1;
    memcpy(hb, host, n); hb[n] = '\0';
    char *hs = hb;
    while (*hs == ' ' || *hs == '\t') hs++;
    if (hs != hb) memmove(hb, hs, strlen(hs) + 1);
    char *colon = strchr(hb, ':'); if (colon) *colon = '\0';
    char *he = hb + strlen(hb);
    while (he > hb && (he[-1] == ' ' || he[-1] == '\t')) he--;
    *he = '\0';

    char dl[2048];
    snprintf(dl, sizeof(dl), "%s", domains ? domains : "");
    char *save = NULL;
    for (char *tok = strtok_s(dl, ",", &save); tok; tok = strtok_s(NULL, ",", &save)) {
        char *t = tok;
        while (*t == ' ' || *t == '\t') t++;
        char *e = t + strlen(t);
        while (e > t && (e[-1] == ' ' || e[-1] == '\t')) e--;
        if ((size_t)(e - t) == strlen(hb) && _strnicmp(t, hb, strlen(hb)) == 0) return 1;
    }
    return 0;
}

/* Validate the request Host header against the configured domain list.
 * Returns 1 when the host is allowed or no Host header is present, 0 when
 * the request must be rejected. */
static int http_check_host(http_ctx_t *c) {
    const char *r = http_req_buf(c);
    size_t rl = c->rlen;
    for (size_t i = 0; i + 5 <= rl; i++) {
        if (_strnicmp(r + i, "Host:", 5) == 0) {
            const char *hv = r + i + 5;
            size_t hl = 0;
            while (hv + hl < r + rl && hv[hl] != '\r' && hv[hl] != '\n') hl++;
            return http_host_allowed(hv, hl, c->domains);
        }
    }
    return 1;
}

/* Find the Host header value. Searches only the header block (before the
 * empty line) and matches "Host:" at a line start. Returns 1 and fills
 * *hv_out/*hl_out on success, 0 when no Host header is present. */
static int http_find_host(const char *r, size_t rl, const char **hv_out, size_t *hl_out) {
    size_t hend = rl;
    for (size_t i = 0; i + 3 < rl; i++) {
        if (r[i] == '\r' && r[i + 1] == '\n' && r[i + 2] == '\r' && r[i + 3] == '\n') { hend = i; break; }
        if (r[i] == '\n' && r[i + 1] == '\n') { hend = i; break; }
    }
    for (size_t i = 0; i + 5 <= hend; i++) {
        int at_line = (i == 0) || (r[i - 1] == '\n');
        if (!at_line) continue;
        size_t j = i;
        while (j < hend && (r[j] == ' ' || r[j] == '\t')) j++;
        if (j + 5 > hend) continue;
        if (_strnicmp(r + j, "Host:", 5) != 0) continue;
        const char *hv = r + j + 5;
        size_t hl = 0;
        while (hv + hl < r + hend && hv[hl] != '\r' && hv[hl] != '\n') hl++;
        if (hv_out) *hv_out = hv;
        if (hl_out) *hl_out = hl;
        return 1;
    }
    return 0;
}

/* Send a "301 Moved Permanently" redirect from www. host to the bare domain.
 * Returns 1 when a redirect was sent (caller must stop processing), else 0.
 * Keeps the original scheme (http/https), port (if present) and request URI:
 *   http://www.localhost:81/a?b=c  -> http://localhost:81/a?b=c
 *   https://www.localhost/a         -> https://localhost/a
 * Redirect applies only when www_redirect is enabled and the bare domain
 * (Host without the "www." prefix) is in the allowed "domains" list. */
static int http_handle_www_redirect(http_server_t *http, http_ctx_t *c, const char *uri) {
    int enabled = c ? c->www_redirect : (http ? http->www_redirect : DEF_WWW_REDIRECT);
    if (!enabled) return 0;
    if (!http || !c || !uri) return 0;
    const char *r = http_req_buf(c);
    if (!r || c->rlen == 0) return 0;
    const char *hv = NULL;
    size_t hl = 0;
    if (!http_find_host(r, c->rlen, &hv, &hl)) return 0;

    char hb[1024];
    size_t n = hl < sizeof(hb) - 1 ? hl : sizeof(hb) - 1;
    memcpy(hb, hv, n); hb[n] = '\0';
    char *s = hb;
    while (*s == ' ' || *s == '\t') s++;
    if (s != hb) memmove(hb, s, strlen(s) + 1);
    char *he = hb + strlen(hb);
    while (he > hb && (he[-1] == ' ' || he[-1] == '\t')) he--;
    *he = '\0';

    /* Split off an optional :port suffix (kept as-is for Location). */
    char port_suffix[64] = {0};
    char *colon = strchr(hb, ':');
    if (colon) {
        size_t pl = strlen(colon);
        if (pl >= sizeof(port_suffix)) return 0;
        memcpy(port_suffix, colon, pl + 1);
        *colon = '\0';
        char *pe = hb + strlen(hb);
        while (pe > hb && (pe[-1] == ' ' || pe[-1] == '\t')) pe--;
        *pe = '\0';
    }
    if (_strnicmp(hb, "www.", 4) != 0) return 0;
    const char *bare = hb + 4;
    if (bare[0] == '\0') return 0;
    /* Redirect only when the bare domain itself is allowed. */
    if (!http_host_allowed(bare, strlen(bare), c->domains)) return 0;

    const char *scheme = c->is_https ? "https" : "http";
    const char *path = (uri[0] == '\0') ? "/" : uri;
    char location[4096];
    if (path[0] == '/') snprintf(location, sizeof(location), "%s://%s%s%s", scheme, bare, port_suffix, path);
    else snprintf(location, sizeof(location), "%s://%s%s/%s", scheme, bare, port_suffix, path);

    char date_buf[128];
    http_date_gmt(date_buf, sizeof(date_buf));
    char hdr[8192];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 301 Moved Permanently\r\nServer: %s\r\nDate: %s\r\n"
        "Location: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        http_srv_name(c), date_buf, location);
    if (hlen > 0) resp_send(c, hdr, (size_t)hlen);
#ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[redirect] www -> %s\n", location);
#endif
    http_update_status_stats(http, 301);
    return 1;
}

// Find a substring ignoring case
static const char *http_strcasestr_custom(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (const char *p = haystack; *p; p++) {
        if (_strnicmp(p, needle, strlen(needle)) == 0) return p;
    }
    return NULL;
}

// Convert a hex digit to its value, or -1 if invalid
static int http_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a decimal integer from s up to end (saturates at INT32_MAX)
static long long http_parse_decimal(const char *s, const char *end) {
    long long v = 0; int any = 0;
    while (s < end && *s >= '0' && *s <= '9') {
        if (v > 0x7FFFFFFFLL / 10) return 0x7FFFFFFFLL;
        v = v * 10 + (*s - '0'); s++; any = 1;
    }
    return any ? v : 0;
}

// Current UTC time formatted as an RFC 7231 HTTP date (thread-safe)
static void http_date_gmt(char *buf, size_t n) {
    static const char *wd[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char *mo[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
#ifdef _WIN32
    SYSTEMTIME st;
    GetSystemTime(&st);
    snprintf(buf, n, "%s, %02u %s %04u %02u:%02u:%02u GMT",
             wd[st.wDayOfWeek % 7], (unsigned)st.wDay, mo[(st.wMonth - 1) % 12],
             (unsigned)st.wYear, (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
#else
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    snprintf(buf, n, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             wd[tmv.tm_wday % 7], tmv.tm_mday, mo[tmv.tm_mon % 12],
             tmv.tm_year + 1900, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
#endif
}

// Allocate and URL-decode a string (+ -> space, %XX -> byte)
static char *http_url_decode_alloc(const char *src, size_t len) {
    char *dst = (char *)malloc(len + 1);
    if (!dst) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        if (src[i] == '%' && i + 2 < len) {
            int hi = http_hex_val(src[i+1]);
            int lo = http_hex_val(src[i+2]);
            if (hi >= 0 && lo >= 0) {
                dst[j++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        if (src[i] == '+') { dst[j++] = ' '; }
        else { dst[j++] = src[i]; }
        i++;
    }
    dst[j] = '\0';
    return dst;
}

// Extract a header value following a given key
static char *http_extract_header_value(const char *header_line, const char *key) {
    size_t klen = strlen(key);
    const char *p = strstr(header_line, key);
    if (!p) return NULL;
    p += klen;
    while (*p == ' ' || *p == ':') p++;
    char *end = strchr(p, '\r');
    if (!end) end = strchr(p, '\n');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    char *val = (char *)malloc(len + 1);
    memcpy(val, p, len); val[len] = '\0';
    while (len > 0 && (val[len-1]==' '||val[len-1]=='\r'||val[len-1]=='\n')) { val[--len] = '\0'; }
    return val;
}

// Parse name and filename out of a Content-Disposition header
static void http_parse_content_disposition(const char *cd_header, char **name, char **filename) {
    const char *np = strstr(cd_header, "name=\"");
    if (np) {
        np += 6;
        const char *ne = strchr(np, '"');
        if (ne) {
            size_t len = (size_t)(ne - np);
            *name = (char *)malloc(len + 1);
            memcpy(*name, np, len); (*name)[len] = '\0';
        }
    }
    const char *fp = strstr(cd_header, "filename=\"");
    if (fp) {
        fp += 10;
        const char *fe = strchr(fp, '"');
        if (fe) {
            size_t len = (size_t)(fe - fp);
            *filename = (char *)malloc(len + 1);
            memcpy(*filename, fp, len); (*filename)[len] = '\0';
        }
    }
}

// Initialize a SHA-1 context
static void http_sha1_init(http_sha1_ctx_t *ctx) {
    ctx->h[0] = 0x67452301; ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE; ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
}

// Rotate a 32-bit value left by n bits
static uint32_t http_sha1_rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

// Process one 64-byte SHA-1 block
static void http_sha1_process(http_sha1_ctx_t *ctx, const unsigned char *block) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)block[i*4]<<24 | (uint32_t)block[i*4+1]<<16 |
               (uint32_t)block[i*4+2]<<8 | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 80; i++) w[i] = http_sha1_rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1);
    uint32_t a=ctx->h[0],b=ctx->h[1],c=ctx->h[2],d=ctx->h[3],e=ctx->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b&c)|((~b)&d); k = 0x5A827999; }
        else if (i < 40) { f = b^c^d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b&c)|(b&d)|(c&d); k = 0x8F1BBCDC; }
        else             { f = b^c^d; k = 0xCA62C1D6; }
        uint32_t temp = http_sha1_rotl(a,5) + f + e + k + w[i];
        e=d; d=c; c=http_sha1_rotl(b,30); b=a; a=temp;
    }
    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d; ctx->h[4]+=e;
}

// Compute the SHA-1 digest of a message
static void http_sha1(const unsigned char *msg, size_t len, unsigned char out[20]) {
    http_sha1_ctx_t ctx;
    http_sha1_init(&ctx);
    size_t pos = 0;
    while (pos + 64 <= len) { http_sha1_process(&ctx, msg + pos); pos += 64; }
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    size_t rem = len - pos;
    if (rem > 0) memcpy(buf, msg + pos, rem);
    buf[rem] = 0x80;
    uint64_t bit_len = (uint64_t)len * 8;
    if (rem >= 56) { http_sha1_process(&ctx, buf); memset(buf, 0, sizeof(buf)); }
    for (int k = 0; k < 8; k++) buf[56 + k] = (unsigned char)(bit_len >> (56 - 8 * k));
    http_sha1_process(&ctx, buf);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (unsigned char)(ctx.h[i] >> 24);
        out[i*4+1] = (unsigned char)(ctx.h[i] >> 16);
        out[i*4+2] = (unsigned char)(ctx.h[i] >> 8);
        out[i*4+3] = (unsigned char)ctx.h[i];
    }
}

// Base64-encode data into out
static void http_base64_encode(const unsigned char *in, size_t len, char *out) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    while (i + 2 < len) {
        out[o++] = b64[(in[i]>>2)&0x3F];
        out[o++] = b64[((in[i]&0x3)<<4)|((in[i+1]>>4)&0xF)];
        out[o++] = b64[((in[i+1]&0xF)<<2)|((in[i+2]>>6)&0x3)];
        out[o++] = b64[in[i+2]&0x3F];
        i += 3;
    }
    if (i + 1 < len) {
        out[o++] = b64[(in[i]>>2)&0x3F];
        out[o++] = b64[((in[i]&0x3)<<4)|((in[i+1]>>4)&0xF)];
        out[o++] = b64[((in[i+1]&0xF)<<2)];
        out[o++] = '=';
    } else if (i < len) {
        out[o++] = b64[(in[i]>>2)&0x3F];
        out[o++] = b64[((in[i]&0x3)<<4)];
        out[o++] = '=';
        out[o++] = '=';
    }
    out[o] = '\0';
}

// Stop the worker thread pool (forward declaration)
static void http_p_stop(http_server_t *http);

// Create and configure a listening TCP socket
static SOCKET http_setup(int port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    int r = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&r, sizeof(r));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons((unsigned short)port);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR) { closesocket(s); return INVALID_SOCKET; }
    if (listen(s, SOMAXCONN) == SOCKET_ERROR) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

// Set up the SSL/TLS context for HTTPS
static int http_setup_https(http_server_t *http, const char *cert_file, const char *key_file) {
#ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[https] init SSL context\n");
#endif
    http->ssl_ctx = SSL_CTX_new();
    ssl_set_io_timeout(http->ssl_ctx,http->timeout_io_ms);
    ssl_set_handshake_timeout(http->ssl_ctx,http->timeout_handshake_ms);
    ssl_set_read_poll(http->ssl_ctx,http->timeout_tls_poll_ms);
    ssl_set_flight_timeout(http->ssl_ctx,http->timeout_flight_ms);
    if (!http->ssl_ctx) {
#ifndef HTTP_NO_LOG
        if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_ERROR, "[err] HTTPS: failed to create SSL context\n");
#endif
        return -1;
    }
    if (SSL_CTX_use_certificate_file(http->ssl_ctx, cert_file, SSL_SERVER_RSA_CERT) != 0) {
#ifndef HTTP_NO_LOG
        if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_ERROR, "[err] HTTPS: failed to load certificate: %s\n", cert_file);
#endif
        SSL_CTX_free(http->ssl_ctx); http->ssl_ctx = NULL; return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(http->ssl_ctx, key_file, SSL_SERVER_RSA_KEY) != 0) {
#ifndef HTTP_NO_LOG
        if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_ERROR, "[err] HTTPS: failed to load private key: %s\n", key_file);
#endif
        SSL_CTX_free(http->ssl_ctx); http->ssl_ctx = NULL; return -1;
    }
    if (!SSL_CTX_check_private_key(http->ssl_ctx)) {
#ifndef HTTP_NO_LOG
        if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_ERROR, "[err] HTTPS: private key does not match certificate\n");
#endif
        SSL_CTX_free(http->ssl_ctx); http->ssl_ctx = NULL; return -1;
    }
#ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[https] SSL context ready, port %d\n", http->port);
#endif
    return 0;
}

// Initialize HTTP server with configuration parameters
http_server_t *http_init() {
    http_server_t *http = (http_server_t *)calloc(1, sizeof(http_server_t));
    if (!http) return NULL;

    http->port = DEF_PORT;
    http->ssl_use = true;
    http->max_clients = MAX_CLIENTS;
    http->timeout_io_ms = TIMEOUT_IO;
    http->timeout_handshake_ms = TIMEOUT_HANDSHAKE;
    http->timeout_tls_poll_ms = TIMEOUT_TLS_POLL;
    http->timeout_flight_ms = TIMEOUT_FLIGHT;
    http->timeout_accept_ms = TIMEOUT_ACCEPT;
    http->worker_threads = NWORKERS;
    http->max_body_mb = DEF_MAX_BODY_MB;
    http->log_output = HTTP_LOG_OUTPUT_CONSOLE;
    http->log_level = HTTP_LOG_LEVEL_INFO;
    http->root = DEF_ROOT;
    http->upload_dir = DEF_UPLOAD_DIR;
    http->cert_file = DEF_CERT_FILE;
    http->key_file = DEF_KEY_FILE;
    http->log_file = DEF_LOG_FILE;
    http->server_name = DEF_SERVER_NAME;
    http->domains = DEF_DOMAINS;
    http->www_redirect = DEF_WWW_REDIRECT;

    http->listen_fd = INVALID_SOCKET;
    http->ssl_ctx = NULL;
    http->running = 0;
    http->shutdown = 0;
    http->total_req = 0;
    http->status_2xx = 0;
    http->status_3xx = 0;
    http->status_4xx = 0;
    http->status_5xx = 0;
    http->start_time = time(NULL);

    memset(http->ssl_conns, 0, sizeof(http->ssl_conns));
    memset(http->ctx, 0, sizeof(http->ctx));
    memset(&http->pool, 0, sizeof(http->pool));
    mtx_init(&http->ctx_lock);
    http->reaper_on = 0;

    http->router.capacity = HTTP_MAX_ROUTES_INITIAL;
    http->router.entries = (http_route_entry_t *)calloc((size_t)http->router.capacity, sizeof(http_route_entry_t));
    if (!http->router.entries) { free(http); return NULL; }
    return http;
}

// Release HTTP server resources and stop all threads
void http_free(http_server_t *http) {
    if (!http) return;
    http->shutdown = 1;
    if (http->listen_fd != INVALID_SOCKET) { closesocket(http->listen_fd); http->listen_fd = INVALID_SOCKET; }
    if (http->ssl_use) {
#ifndef HTTP_NO_LOG
        if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[shutdown] HTTPS server stopped\n");
#endif
    }
#ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[shutdown] HTTP server stopped\n");
#endif
    http_p_stop(http);
    if (http->router.entries) { free(http->router.entries); http->router.entries = NULL; }
    if (http->ssl_ctx) { SSL_CTX_free(http->ssl_ctx); http->ssl_ctx = NULL; }
    mtx_destroy(&http->ctx_lock);
    sock_cleanup();
    free(http);
}

// Register a route handler for method+path
void http_route(http_server_t *http, const char *method, const char *path,
                int (*handler)(http_server_t *http, http_ctx_t *c, const char *method, const char *uri,
                               const char *body, size_t body_len)) {
    if (!http || !handler) return;
    if (http->router.count >= http->router.capacity) {
        int new_cap = (http->router.capacity > 0) ? http->router.capacity * 2 : HTTP_MAX_ROUTES_INITIAL;
        if (new_cap > HTTP_MAX_ROUTES) new_cap = HTTP_MAX_ROUTES;
        http_route_entry_t *new_entries = (http_route_entry_t *)realloc(http->router.entries,
                                                                        (size_t)new_cap * sizeof(http_route_entry_t));
        if (!new_entries) return;
        http->router.entries = new_entries;
        http->router.capacity = new_cap;
    }
    http->router.entries[http->router.count].method = method;
    http->router.entries[http->router.count].path = path;
    http->router.entries[http->router.count].handler = handler;
    http->router.count++;
}

// Non-blocking readiness check for a socket
static int http_sock_poll(SOCKET fd, int wait_write) {
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 0;
    return wait_write ? select((int)fd + 1, NULL, &fds, NULL, &tv)
                      : select((int)fd + 1, &fds, NULL, NULL, &tv);
}

// Wait up to timeout_ms for socket readiness (0 = block indefinitely)
static int http_sock_wait(SOCKET fd, int wait_write, int timeout_ms) {
    fd_set fds; FD_ZERO(&fds); FD_SET(fd, &fds);
    if (timeout_ms == 0)
        return wait_write ? select((int)fd + 1, NULL, &fds, NULL, NULL)
                          : select((int)fd + 1, &fds, NULL, NULL, NULL);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return wait_write ? select((int)fd + 1, NULL, &fds, NULL, &tv)
                      : select((int)fd + 1, &fds, NULL, NULL, &tv);
}

// Blocking recv with I/O timeout; returns 0 on peer close, -1 on error/timeout
static int http_sock_recv(SOCKET fd, char *buf, int len, int timeout_ms) {
    if ((int)fd <= 0) return -1;
    for (;;) {
        if (http_sock_wait(fd, 0, timeout_ms) <= 0) return -1;
        int n = recv(fd, buf, (size_t)len, 0);
        if (n == 0) return 0;
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) continue;
            return -1;
        }
        return n;
    }
}

// Blocking send of the whole buffer; returns bytes written or -1
static int http_sock_send_all(SOCKET fd, const char *buf, int len, int timeout_ms) {
    int total = 0;
    while (total < len) {
        if (http_sock_wait(fd, 1, timeout_ms) <= 0) return total > 0 ? total : -1;
        int n = send(fd, buf + total, (size_t)(len - total), 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) continue;
            return total > 0 ? total : -1;
        }
        if (n == 0) return total > 0 ? total : -1;
        total += n;
    }
    return total;
}

// Apply a bounded recv/send timeout to a socket (ms; 0 = no timeout).
// Without this a stalled client pins the worker thread forever inside
// recv()/send() (the TLS layer calls raw blocking recv()/send()).
static void http_sock_set_io_timeout(SOCKET s, int ms) {
    if (ms <= 0) return;
#ifdef _WIN32
    int to = ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&to, sizeof(to));
#else
    struct timeval to;
    to.tv_sec = ms / 1000;
    to.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
#endif
}

// Pool worker thread (forward declaration)
static void *http_worker(void *p);
// Close a connection and free its resources (forward declaration)
static void http_conn_close(http_server_t *http, http_ctx_t *c);
// Serve a connection (forward declaration)
static void http_serve_conn(http_server_t *http, http_ctx_t *c);

// Start the worker thread pool
void http_p_start(http_server_t *http, int n, int sz) {
    http_pool_t *pool = &http->pool;
    memset(pool, 0, sizeof(http_pool_t));
    pool->nt = (unsigned)(n > 0 ? n : 1);
    pool->qs = sz < 1 ? 1 : sz;
    pool->q = (http_ctx_t **)calloc((size_t)pool->qs, sizeof(http_ctx_t *));
    evt_init(&pool->ev);
    pool->th = (thr_t *)calloc((size_t)pool->nt, sizeof(thr_t));
    mtx_init(&pool->cs);
    for (unsigned i = 0; i < pool->nt; i++)
        thr_create(&pool->th[i], http_worker, http);
}

// Stop the worker thread pool and wait for all workers
void http_p_stop(http_server_t *http) {
    http_pool_t *pool = &http->pool;
    if (!pool->q) return;
    {
        /* Unblock workers stuck in recv()/send() by shutting down every
         * live connection. Collect fds under the ctx lock; the worker that
         * owns a socket performs the final close/free. */
        SOCKET dead[MAX_CLIENTS];
        int ndead = 0;
        mtx_lock(&http->ctx_lock);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            http_ctx_t *c = http->ctx[i];
            if (c && (int)c->fd > 0) { c->reaped = 1; dead[ndead++] = c->fd; }
        }
        mtx_unlock(&http->ctx_lock);
        for (int i = 0; i < ndead; i++) shutdown(dead[i], SD_BOTH);
    }
    for (unsigned i = 0; i < pool->nt; i++) evt_signal(&pool->ev);
    for (unsigned i = 0; i < pool->nt; i++) thr_join(&pool->th[i]);
    if (http->reaper_on) { thr_join(&http->reaper); http->reaper_on = 0; }
    free(pool->th);
    mtx_lock(&pool->cs);
    while (pool->qt > pool->qh) {
        http_conn_close(http, pool->q[pool->qh % pool->qs]);
        pool->qh++;
    }
    mtx_unlock(&pool->cs);
    mtx_destroy(&pool->cs);
    free(pool->q);
    evt_destroy(&pool->ev);
    pool->q = NULL; pool->th = NULL;
}

// Queue an accepted connection for a worker thread
static void http_p_push(http_server_t *http, http_ctx_t *c) {
    http_pool_t *pool = &http->pool;
    mtx_lock(&pool->cs);
    if (pool->qt - pool->qh < pool->qs) {
        pool->q[pool->qt % pool->qs] = c;
        pool->qt++;
        mtx_unlock(&pool->cs);
        evt_signal(&pool->ev);
    } else {
        mtx_unlock(&pool->cs);
        http_conn_close(http, c);
    }
}

// Serve a connection end-to-end in this worker thread
static void *http_worker(void *p) {
    http_server_t *http = (http_server_t *)p;
    http_pool_t *pool = &http->pool;
    for (;;) {
        if (http->shutdown) break;
        evt_wait(&pool->ev);
        if (http->shutdown) break;
        http_ctx_t *c = NULL;
        mtx_lock(&pool->cs);
        if (pool->qt > pool->qh) {
            c = pool->q[pool->qh % pool->qs];
            pool->qh++;
            if (pool->qt > pool->qh) evt_signal(&pool->ev);
        }
        mtx_unlock(&pool->cs);
        if (!c) continue;
        http_serve_conn(http, c);
        http_conn_close(http, c);
    }
    return NULL;
}

// Allocate a connection context from the server table
static http_ctx_t *http_ctx_alloc(http_server_t *http, SOCKET fd, int is_https) {
    mtx_lock(&http->ctx_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!http->ctx[i]) {
            http_ctx_t *c = (http_ctx_t *)calloc(1, sizeof(http_ctx_t));
            if (c) {
                c->fd = fd;
                c->state = S_IDLE;
                c->is_https = is_https;
                c->timeout_io_ms = http->timeout_io_ms;
                c->server_name = http->server_name;
                c->domains = http->domains;
                c->www_redirect = http->www_redirect;
                unsigned long now = compat_tick();
                c->connect_tick = now;
                c->last_active = now;
                http->ctx[i] = c;
                mtx_unlock(&http->ctx_lock);
                return c;
            }
        }
    }
    mtx_unlock(&http->ctx_lock);
    return NULL;
}

// Remove a connection context from the server table
static void http_ctx_unregister(http_server_t *http, http_ctx_t *c) {
    mtx_lock(&http->ctx_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (http->ctx[i] == c) { http->ctx[i] = NULL; break; }
    }
    mtx_unlock(&http->ctx_lock);
}

// Close a connection and free its resources
static void http_conn_close(http_server_t *http, http_ctx_t *c) {
    if (!c) return;
    if (c->_ssl) {
        if (c->handshake_state && (int)c->fd > 0) SSL_shutdown((SSL *)c->_ssl);
        SSL_free((SSL *)c->_ssl);
        c->_ssl = NULL;
    }
    if ((int)c->fd > 0) {
        shutdown((SOCKET)c->fd, SD_BOTH);
        closesocket((SOCKET)c->fd);
        c->fd = INVALID_SOCKET;
    }
    free(c->wb); c->wb = NULL;
    free(c->big); c->big = NULL; c->big_cap = 0;
    http_ctx_unregister(http, c);
    free(c);
}

// Idle reaper: closes connections that stay silent too long before the full
// request arrives (silent connects, half-finished TLS handshakes, slowloris
// trickling). Without this a stalled client pins a worker thread forever.
// Only shutdown() is issued here: the worker still owning the socket wakes
// up with an I/O error and does the close/free itself - no use-after-free.
static void *http_reaper(void *p) {
    http_server_t *http = (http_server_t *)p;
    SOCKET dead[128];
    for (;;) {
#ifdef _WIN32
        Sleep(1000);
#else
        { struct timespec ts = { 1, 0 }; nanosleep(&ts, NULL); }
#endif
        if (http->shutdown) break;
        unsigned long now = compat_tick();
        const unsigned long idle_ms = 30000; /* max silence before request is read */
        int ndead = 0;
        mtx_lock(&http->ctx_lock);
        for (int i = 0; i < MAX_CLIENTS && ndead < (int)(sizeof(dead) / sizeof(dead[0])); i++) {
            http_ctx_t *c = http->ctx[i];
            if (c && !c->reaped && !c->req_done && (int)c->fd > 0 &&
                now - c->last_active >= idle_ms) {
                c->reaped = 1;
                dead[ndead++] = c->fd;
            }
        }
        mtx_unlock(&http->ctx_lock);
        for (int i = 0; i < ndead; i++) shutdown(dead[i], SD_BOTH);
    }
    return NULL;
}

// Return the effective raw request buffer (dynamic or inline)
char *http_req_buf(http_ctx_t *c) {
    return c ? (c->big ? c->big : c->rb) : NULL;
}

// Send data through the socket (TLS or plain)
static void resp_send(http_ctx_t *c, const void *data, size_t len) {
    if (!c || !data || len == 0 || (int)c->fd <= 0) return;
    if (c->is_https && c->_ssl) {
        SSL_write((SSL *)c->_ssl, data, (int)len);
    } else {
        http_sock_send_all(c->fd, (const char *)data, (int)len, c->timeout_io_ms);
    }
}

// Send JSON HTTP response
void http_send_json_response(http_server_t *http, http_ctx_t *c, int status, const char *json_body) {
    (void)http;
    char date_buf[128];
    http_date_gmt(date_buf, sizeof(date_buf));
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        status,
        status == 200 ? "OK" : status == 201 ? "Created" : status == 204 ? "No Content" :
        status == 400 ? "Bad Request" : status == 404 ? "Not Found" :
        status == 408 ? "Request Timeout" : "Internal Server Error",
        http_srv_name(c), date_buf, (int)strlen(json_body));
    char *resp = (char *)malloc((size_t)hlen + strlen(json_body));
    memcpy(resp, hdr, (size_t)hlen);
    memcpy(resp + hlen, json_body, strlen(json_body));
    resp_send(c, resp, (size_t)(hlen + (int)strlen(json_body)));
    free(resp);
}

// Send text HTTP response
void http_send_text_response(http_server_t *http, http_ctx_t *c, int status, const char *text) {
    (void)http;
    char date_buf[128];
    http_date_gmt(date_buf, sizeof(date_buf));
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        status,
        status == 200 ? "OK" : status == 201 ? "Created" :
        status == 400 ? "Bad Request" : status == 404 ? "Not Found" : "Internal Server Error",
        http_srv_name(c), date_buf, (int)strlen(text));
    char *resp = (char *)malloc((size_t)hlen + strlen(text));
    memcpy(resp, hdr, (size_t)hlen);
    memcpy(resp + hlen, text, strlen(text));
    resp_send(c, resp, (size_t)(hlen + (int)strlen(text)));
    free(resp);
}

// Send HTML HTTP response
void http_send_html_response(http_server_t *http, http_ctx_t *c, int status, const char *html) {
    (void)http;
    char date_buf[128];
    http_date_gmt(date_buf, sizeof(date_buf));
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\nServer: %s\r\nDate: %s\r\n"
        "Content-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        status,
        status == 200 ? "OK" : status == 400 ? "Bad Request" : "Internal Server Error",
        http_srv_name(c), date_buf, (int)strlen(html));
    char *resp = (char *)malloc((size_t)hlen + strlen(html));
    memcpy(resp, hdr, (size_t)hlen);
    memcpy(resp + hlen, html, strlen(html));
    resp_send(c, resp, (size_t)(hlen + (int)strlen(html)));
    free(resp);
}

// Append chunked-encoded data to write buffer
void http_write_chunked(http_ctx_t *c, const char *d, size_t dl) {
    for (size_t off = 0; off < dl; off += 65536) {
        size_t piece = dl - off; if (piece > 65536) piece = 65536;
        char hex[8]; int hl = snprintf(hex, 8, "%zx\r\n", (size_t)piece);
        c->wb = (char *)realloc(c->wb, c->wlen + (size_t)hl + piece + 2);
        memcpy(c->wb + c->wlen, hex, (size_t)hl); c->wlen += (size_t)hl;
        memcpy(c->wb + c->wlen, d + off, piece); c->wlen += piece;
        const char *cr = "\r\n"; memcpy(c->wb + c->wlen, cr, 2); c->wlen += 2;
    }
    c->wb = (char *)realloc(c->wb, c->wlen + 5);
    memcpy(c->wb + c->wlen, "0\r\n\r\n", 5); c->wlen += 5;
}

// Get MIME type from file extension
const char *http_mime_type(const char *p) {
    const char *e = strrchr(p, '.');
    if (!e) return "application/octet-stream";
    #define M(x,t) if (!_stricmp(e, x)) return t
    M(".html", "text/html; charset=utf-8"); M(".htm", "text/html; charset=utf-8");
    M(".css", "text/css; charset=utf-8"); M(".js", "application/javascript");
    M(".json", "application/json"); M(".png", "image/png");
    M(".jpg", "image/jpeg"); M(".jpeg", "image/jpeg"); M(".gif", "image/gif");
    M(".svg", "image/svg+xml"); M(".ico", "image/x-icon");
    M(".txt", "text/plain; charset=utf-8");
    return "application/octet-stream";
}

#ifndef HTTP_NO_GZIP

// Serve a pre-compressed.gz file if the client accepts gzip
static void http_sfile_gz(http_server_t *http, http_ctx_t *c, const char *rel, const char *raw_hdr, size_t hdr_len) {
    (void)hdr_len;
    if (!http_client_accepts_gzip(raw_hdr, hdr_len)) return;
    char gz_path[2048];
    int gz_name_len = snprintf(gz_path, sizeof(gz_path), "%s%s.gz", http->root, rel);
    if (gz_name_len < 0 || gz_name_len >= (int)sizeof(gz_path)) return;
    FILE *f = fopen(gz_path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long gz_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (gz_size <= 0 || gz_size > 100 * 1024 * 1024) { fclose(f); return; }
    char *gz_data = (char *)malloc((size_t)gz_size + 1);
    if (!gz_data) { fclose(f); return; }
    size_t gz_read = fread(gz_data, 1, (size_t)gz_size, f);
    fclose(f);
    if ((long)gz_read != gz_size) { free(gz_data); return; }
    char db[128];
    http_date_gmt(db, sizeof(db));
    char h[400];
    int hl = snprintf(h, sizeof(h),
        "Server: %s\r\nDate: %s\r\nContent-Type: %s\r\n"
        "Content-Encoding: gzip\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
        http_srv_name(c), db, http_mime_type(rel), gz_size);
    c->wb = (char *)realloc(c->wb, c->wlen + (size_t)hl + (size_t)gz_size);
    memcpy(c->wb + c->wlen, h, (size_t)hl); c->wlen += (size_t)hl;
    memcpy(c->wb + c->wlen, gz_data, (size_t)gz_read); c->wlen += (size_t)gz_read;
    free(gz_data);
}

// Serve a file compressed on the fly with gzip
static void http_sfile_gzip_compress(http_server_t *http, http_ctx_t *c, const char *rel, const char *raw_hdr, size_t hdr_len) {
    (void)hdr_len;
    if (!http_client_accepts_gzip(raw_hdr, hdr_len)) return;
    char path[2048];
    snprintf(path, sizeof(path), "%s%s", http->root, rel);
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0 || file_size > 100 * 1024 * 1024) { fclose(f); return; }
    char *raw_data = (char *)malloc((size_t)file_size + 1);
    if (!raw_data) { fclose(f); return; }
    size_t read_bytes = fread(raw_data, 1, (size_t)file_size, f);
    fclose(f);
    if ((long)read_bytes != file_size) { free(raw_data); return; }
    uLongf compressed_len = compressBound((uLong)read_bytes);
    unsigned char *compressed = (unsigned char *)malloc((size_t)compressed_len);
    if (!compressed) { free(raw_data); return; }
    int rc = compress(compressed, &compressed_len, (const Bytef *)raw_data, (uLong)read_bytes);
    if (rc != Z_OK || compressed_len >= read_bytes) {
        free(compressed); free(raw_data);
        char db[128];
        http_date_gmt(db, sizeof(db));
        char h[300]; int hl = snprintf(h, sizeof(h),
            "HTTP/1.1 200 OK\r\nServer: %s\r\nDate: %s\r\n"
            "Content-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
            http_srv_name(c), db, http_mime_type(rel), file_size);
        c->wb = (char *)realloc(c->wb, c->wlen + (size_t)hl + (size_t)read_bytes);
        memcpy(c->wb + c->wlen, h, (size_t)hl); c->wlen += (size_t)hl;
        memcpy(c->wb + c->wlen, raw_data, read_bytes); c->wlen += read_bytes;
        free(raw_data);
        return;
    }
    char db[128];
    http_date_gmt(db, sizeof(db));
    char h[400]; int hl = snprintf(h, sizeof(h),
        "HTTP/1.1 200 OK\r\nServer: %s\r\nDate: %s\r\n"
        "Content-Type: %s\r\nContent-Encoding: gzip\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
        http_srv_name(c), db, http_mime_type(rel), (unsigned long)compressed_len);
    c->wb = (char *)realloc(c->wb, c->wlen + (size_t)hl + (size_t)compressed_len);
    memcpy(c->wb + c->wlen, h, (size_t)hl); c->wlen += (size_t)hl;
    memcpy(c->wb + c->wlen, compressed, (size_t)compressed_len); c->wlen += (size_t)compressed_len;
    free(compressed); free(raw_data);
}

#endif // HTTP_NO_GZIP

// Serve static file with optional gzip
void http_sfile(http_server_t *http, http_ctx_t *c, const char *rel) {
#ifndef HTTP_NO_GZIP
    http_sfile_gz(http, c, rel, http_req_buf(c), c->rlen < sizeof(c->rb) ? c->rlen : 0);
    if (c->wlen > 0 && strchr((const char *)c->wb + c->wlen - 100, '4') == NULL) {
        if (strstr((char *)c->wb, "Content-Encoding: gzip")) return;
    }
#endif
    char path[2048]; snprintf(path, sizeof(path), "%s%s", http->root, rel);
    FILE *f = fopen(path, "rb");
    if (!f) {
        char h[512]; int hl = snprintf(h, sizeof(h),
            "HTTP/1.1 404 Not Found\r\nServer: %s\r\n"
            "Content-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n"
            "<!DOCTYPE html><html><head><title>404</title></head>"
            "<body><h1>404 Not Found</h1></body></html>",
            http_srv_name(c));
        c->wb = (char *)realloc(c->wb, c->wlen + (size_t)hl); memcpy(c->wb + c->wlen, h, (size_t)hl); c->wlen += (size_t)hl;
        return;
    }
    fseek(f, 0, SEEK_END); long fl = ftell(f); fseek(f, 0, SEEK_SET);
    if (fl <= 0 || fl > 100 * 1024 * 1024) { fclose(f); return; }
    char *b = (char *)malloc((size_t)fl + 1); size_t nr = fread(b, 1, (size_t)fl, f); fclose(f);
    char db[128];
    http_date_gmt(db, sizeof(db));
    char h[300]; int hl = snprintf(h, sizeof(h),
        "HTTP/1.1 200 OK\r\nServer: %s\r\nDate: %s\r\n"
        "Content-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
        http_srv_name(c), db, http_mime_type(rel), fl);
    c->wb = (char *)realloc(c->wb, c->wlen + (size_t)hl + nr);
    memcpy(c->wb + c->wlen, h, (size_t)hl); c->wlen += (size_t)hl;
    memcpy(c->wb + c->wlen, b, nr); c->wlen += nr;
    free(b);
}

// HTML-escape special characters in string
void http_html_escape_str(char *dst, size_t dst_size, const char *s) {
    size_t j = 0;
    for (size_t i = 0; s[i] && j < dst_size - 1; i++) {
        switch (s[i]) {
            case '&': if (j + 5 < dst_size) { memcpy(dst + j, "&amp;", 5); j += 5; } break;
            case '<': if (j + 4 < dst_size) { memcpy(dst + j, "&lt;", 4); j += 4; } break;
            case '>': if (j + 4 < dst_size) { memcpy(dst + j, "&gt;", 4); j += 4; } break;
            case '"': if (j + 6 < dst_size) { memcpy(dst + j, "&quot;", 6); j += 6; } break;
            default: dst[j++] = s[i]; break;
        }
    }
    dst[j] = '\0';
}

// Extract Content-Type from request headers
const char *http_get_content_type(const char *raw_hdr) {
    const char *p = http_strcasestr_custom(raw_hdr, "Content-Type:");
    if (!p) return NULL;
    p += 13;
    while (*p == ' ') p++;
    static char buf[256];
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < sizeof(buf) - 1) { buf[i++] = *p++; }
    buf[i] = '\0';
    return buf;
}

// Check if client Accept-Encoding includes gzip
#ifndef HTTP_NO_GZIP
int http_client_accepts_gzip(const char *raw, size_t rlen) {
    const char *ae = NULL;
    for (size_t i = 0; i < rlen; i++) {
        if (i + 16 <= rlen && _strnicmp(raw + i, "Accept-Encoding:", 16) == 0) { ae = raw + i + 16; break; }
    }
    if (!ae) return 0;
    while (*ae == ' ') ae++;
    if (strstr(ae, "gzip") || strstr(ae, "*")) return 1;
    return 0;
}
#endif

// Detect path traversal attempts in URI
int http_check_path_traversal(const char *path) {
    if (!path) return 0;
    const char *patterns[] = {"..\\", "../", "..%2f", "..%2F", "%2e%2e", "%2E%2E", "%2e%2E", "%2E%2e", NULL};
    for (int i = 0; patterns[i]; i++) { if (strstr(path, patterns[i])) return 1; }
    const char *p = path;
    while ((p = strchr(p, '\\')) != NULL) {
        if (p > path && *(p - 1) == '.') {
            size_t rest_len = strlen(p);
            if (rest_len >= 2 && p[-2] == '.' && (rest_len == 2 || p[1] == '/' || p[1] == '\\')) return 1;
        }
        p++;
    }
    if (strstr(path, "...") || strstr(path, "....")) return 1;
    return 0;
}

// Check if path matches blocked patterns
int http_is_blocked_path(const char *path) {
    if (!path) return 0;
    for (int i = 0; i < BLOCKED_PATHS_COUNT; i++) {
        const char *pat = http_blocked_paths[i];
        while (*pat == '*') pat++;
        size_t plen = strlen(pat);
        while (plen > 0 && pat[plen - 1] == '*') plen--;
        if (plen == 0) continue;
        size_t path_len = strlen(path);
        for (size_t s = 0; s + plen <= path_len; s++) {
            if (_strnicmp(path + s, pat, plen) == 0) return 1;
        }
    }
    return 0;
}

// Effective max request body in bytes, or SIZE_MAX when unlimited.
static size_t http_max_body_bytes(http_server_t *http) {
    return (http && http->max_body_mb > 0) ? (size_t)http->max_body_mb * 1024 * 1024 : (size_t)-1;
}

// Validate body and header size limits
int http_check_size_limits(size_t body_len, size_t header_len, size_t max_body_bytes) {
    if (max_body_bytes != (size_t)-1 && body_len > max_body_bytes) return 1;
    if (header_len > MAX_HEADER_SIZE) return 2;
    return 0;
}

// Increment status code category counter
void http_update_status_stats(http_server_t *http, int http_status) {
    if (!http) return;
    if (http_status >= 200 && http_status < 300) http->status_2xx++;
    else if (http_status >= 300 && http_status < 400) http->status_3xx++;
    else if (http_status >= 400 && http_status < 500) http->status_4xx++;
    else if (http_status >= 500 && http_status < 600) http->status_5xx++;
}

// Print server runtime statistics to log
void http_print_statistics(http_server_t *http) {
    if (!http) return;
    time_t now = time(NULL);
    double uptime = difftime(now, http->start_time);
    double req_per_sec = (uptime > 0) ? (double)http->total_req / uptime : 0.0;
    #ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "\n[stats] === Server Statistics ===\n");
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats] Uptime: %.0f seconds\n", uptime);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats] Total requests: %ld\n", http->total_req);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats] Req/s: %.2f\n", req_per_sec);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats] Status codes:\n");
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats]   2xx (success):      %ld\n", http->status_2xx);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats]   3xx (redirect):     %ld\n", http->status_3xx);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats]   4xx (client error): %ld\n", http->status_4xx);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats]   5xx (server error): %ld\n", http->status_5xx);
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[stats] =========================\n");
#endif
}

// Flush write buffer to socket
void http_send_buf(http_server_t *http, http_ctx_t *c) {
    (void)http;
    if (!c) return;
    if (c->wlen > 0) {
        if (c->is_https && c->_ssl) {
            int n = SSL_write((SSL *)c->_ssl, (const char *)c->wb, (int)c->wlen);
            if (n < 0) { c->handshake_state = 0; }
        } else {
            int n = http_sock_send_all(c->fd, (const char *)c->wb, (int)c->wlen, c->timeout_io_ms);
            if (n != (int)c->wlen) { c->handshake_state = 0; }
        }
    }
    free(c->wb); c->wb = NULL; c->wlen = 0; c->woff = 0; c->state = S_IDLE;
}

// Parse and dispatch HTTP request
void http_do_parse(http_server_t *http, http_ctx_t *c, const char *raw, size_t rlen) {
    if (!http) return;
    http->total_req++;
    if (raw != c->rb && rlen < sizeof(c->rb)) { memcpy(c->rb, raw, rlen); c->rlen = rlen; }
    else if (raw != c->rb) {
        if (!c->big || c->big_cap < rlen + 1) {
            char *nb = (char *)realloc(c->big, rlen + 1);
            if (!nb) { c->rlen = 0; return; }
            c->big = nb; c->big_cap = rlen + 1;
        }
        memcpy(c->big, raw, rlen); c->big[rlen] = '\0'; c->rlen = rlen;
    }
    http_dispatch_handler(http, c);
    c->pending_write = 1;
}

// Route request to handler or static file
int http_dispatch_handler(http_server_t *http, http_ctx_t *c) {
    char *raw = http_req_buf(c);
    size_t rlen = c->rlen;
    {
        /* big buffers are not NUL-terminated by the reader; terminate now,
         * otherwise strstr() below reads past the heap allocation */
        size_t raw_cap = c->big ? c->big_cap : sizeof(c->rb);
        if (rlen < raw_cap) raw[c->rlen] = '\0';
    }
    if (rlen < 4) { http_send_json_response(http, c, 400, "{\"error\":\"Invalid HTTP request\"}"); http_update_status_stats(http, 400); return 1; }
    char method[16] = {0}, uri[2048] = {0};
    {
        const char *p = raw;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        size_t i = 0;
        while (i < sizeof(method) - 1 && *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            method[i++] = *p++;
        method[i] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        i = 0;
        while (i < sizeof(uri) - 1 && *p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            uri[i++] = *p++;
        uri[i] = '\0';
    }
    #ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[request] %s %s\n", method, uri);
#endif
    if (strlen(uri) > MAX_URI_LENGTH) { http_send_json_response(http, c, 414, "{\"error\":\"URI too long\"}"); return 1; }
    if (http_check_path_traversal(uri)) { http_send_json_response(http, c, 400, "{\"error\":\"Path traversal detected\"}"); http_update_status_stats(http, 400); return 1; }
    if (http_handle_www_redirect(http, c, uri)) return 1;
    if (!http_check_host(c)) { http_send_json_response(http, c, 400, "{\"error\":\"Invalid Host header\"}"); http_update_status_stats(http, 400); return 1; }
    const char *body_start = http_memmem(raw, rlen, "\r\n\r\n", 4);
    if (!body_start) { http_send_json_response(http, c, 400, "{\"error\":\"Invalid HTTP request\"}"); return 1; }
    size_t header_size = (size_t)(body_start - raw);
    body_start += 4;
    long long content_length = 0;
    const char *cl = http_strcasestr_custom(raw, "Content-Length:");
    if (cl) {
        const char *cp = cl + 15;
        while (*cp == ' ' || *cp == '\t') cp++;
        content_length = http_parse_decimal(cp, raw + rlen);
        if (content_length < 0) content_length = 0;
    }
    size_t body_len = (size_t)(rlen - (body_start - raw));
    /* The body cannot be larger than what actually arrived on the wire */
    if (content_length > (long long)body_len) content_length = (long long)body_len;
    if (body_len > (size_t)content_length) body_len = (size_t)content_length;
    int size_err = http_check_size_limits(body_len, header_size, http_max_body_bytes(http));
    if (size_err == 1) { http_send_json_response(http, c, 413, "{\"error\":\"Request body too large\"}"); http_update_status_stats(http, 413); return 1; }
    if (size_err == 2) { http_send_json_response(http, c, 431, "{\"error\":\"Request header too large\"}"); http_update_status_stats(http, 431); return 1; }
    char clean_path[2048] = {0};
    strncpy(clean_path, uri, sizeof(clean_path) - 1);
    char *qs = strchr(clean_path, '?');
    if (qs) *qs = '\0';
    if (http_is_blocked_path(clean_path)) { http_send_json_response(http, c, 403, "{\"error\":\"Access denied\"}"); http_update_status_stats(http, 403); return 1; }
    if (http->router.count > 0) {
        for (int i = 0; i < http->router.count; i++) {
            const http_route_entry_t *e = &http->router.entries[i];
            if (!http_method_matches(e->method, method)) continue;
            if (strcmp(e->path, clean_path) == 0) { e->handler(http, c, method, uri, (char *)body_start, body_len); return 1; }
        }
    }
    char rel[2048];
    size_t plen = strlen(clean_path);
    if (plen > 0 && clean_path[plen - 1] == '/') snprintf(rel, sizeof(rel), "%sindex.html", clean_path);
    else snprintf(rel, sizeof(rel), "%s", clean_path);
    char path[2048]; snprintf(path, sizeof(path), "%s%s", http->root, rel);
    FILE *f = fopen(path, "rb");
    if (!f) {
        char h[512]; int hl = snprintf(h, sizeof(h),
            "HTTP/1.1 404 Not Found\r\nServer: %s\r\n"
            "Content-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n"
            "<!DOCTYPE html><html><head><title>404</title></head><body><h1>404 Not Found</h1></body></html>",
            http_srv_name(c));
        resp_send(c, h, (size_t)hl); http_update_status_stats(http, 404); return 1;
    }
    fseek(f, 0, SEEK_END); long fl = ftell(f); fseek(f, 0, SEEK_SET);
    if (fl <= 0 || fl > 100 * 1024 * 1024) { fclose(f); return 1; }
#ifndef HTTP_NO_GZIP
    int gz_served = 0;
    const char *ae = NULL;
    {
        const char *r = http_req_buf(c); size_t rl = c->rlen;
        for (size_t i = 0; i < rl && i + 16 <= rl; i++) {
            if (_strnicmp(r + i, "Accept-Encoding:", 16) == 0) { ae = r + i + 16; break; }
        }
    }
    if (ae) {
        while (*ae == ' ') ae++;
        if (strstr(ae, "gzip") || strstr(ae, "*")) {
            char gz_path[2048]; snprintf(gz_path, sizeof(gz_path), "%s.gz", path);
            FILE *gf = fopen(gz_path, "rb");
            if (gf) {
                fseek(gf, 0, SEEK_END); long gs = ftell(gf); fseek(gf, 0, SEEK_SET);
                if (gs > 0 && gs < 100 * 1024 * 1024) {
                    char *gz_d = (char *)malloc((size_t)gs + 1);
                    size_t gz_r = fread(gz_d, 1, (size_t)gs, gf); fclose(gf);
                    if ((long)gz_r == gs) {
                        char db[128];
                        http_date_gmt(db, sizeof(db));
                        const char *mt = http_mime_type(rel);
                        char h[400]; int hl = snprintf(h, sizeof(h),
                            "HTTP/1.1 200 OK\r\nServer: %s\r\nDate: %s\r\n"
                            "Content-Type: %s\r\nContent-Encoding: gzip\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
                            http_srv_name(c), db, mt, gs);
                        resp_send(c, h, (size_t)hl);
                        resp_send(c, gz_d, (size_t)gz_r);
                        gz_served = 1;
                        free(gz_d);
                    }
                } else { fclose(gf); }
            }
        }
    }
    if (!gz_served) {
#else
    {
#endif
        char *b = (char *)malloc((size_t)fl + 1); size_t nr = fread(b, 1, (size_t)fl, f); fclose(f);
        char db[128];
        http_date_gmt(db, sizeof(db));
        char h[300]; int hl = snprintf(h, sizeof(h),
            "HTTP/1.1 200 OK\r\nServer: %s\r\nDate: %s\r\n"
            "Content-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\n\r\n",
            http_srv_name(c), db, http_mime_type(rel), fl);
        resp_send(c, h, (size_t)hl);
        resp_send(c, b, nr);
        free(b);
    }
    http_update_status_stats(http, 200);
    return 1;
}

/* Read up to len bytes from a connection (TLS-aware).
 * @param c Connection context.
 * @param buf Destination buffer.
 * @param len Maximum bytes to read.
 * @return Bytes read, or -1 on error/disconnect. */
int http_sock_read_data(http_ctx_t *c, char *buf, int len) {
    if (c->is_https && c->_ssl) return SSL_read((SSL *)c->_ssl, buf, len);
    return recv(c->fd, buf, len, 0);
}

// Read a complete request (headers + Content-Length body); returns 0 when ready
static int http_conn_read_request(http_server_t *http, http_ctx_t *c) {
    (void)http;
    /* Total read deadline: per-chunk gaps are bounded by the socket
     * SO_RCVTIMEO, this additionally bounds the whole assembly so a
     * slowloris trickle cannot pin a worker forever. Assumed minimum
     * legitimate rate: 10 KB/s of body transfer. */
    unsigned long rd_start = compat_tick();
    unsigned long io_eff = (unsigned)(c->timeout_io_ms > 0 ? c->timeout_io_ms : 5000);
    unsigned long rd_deadline = rd_start + io_eff * 12 + 1000; /* headers phase */
    for (;;) {
        if (compat_tick() >= rd_deadline) {
            http_send_json_response(http, c, 408, "{\"error\":\"Request timeout\"}");
            http_update_status_stats(http, 408);
            return -1;
        }
        char *buf = c->big ? c->big : c->rb;
        size_t cap = c->big ? c->big_cap : sizeof(c->rb);
        if (c->rlen >= cap) return -1;
        int n;
        if (c->is_https && c->_ssl) {
            n = SSL_read((SSL *)c->_ssl, buf + c->rlen, (int)(cap - c->rlen));
        } else {
            n = http_sock_recv(c->fd, buf + c->rlen, (int)(cap - c->rlen), c->timeout_io_ms);
        }
        if (n <= 0) {
            return -1;
        }
        c->rlen += (size_t)n;
        c->last_active = compat_tick();

        int hsz = -1;
        for (size_t pos = 0; pos + 3 < c->rlen; pos++) {
            if (buf[pos] == '\r' && buf[pos + 1] == '\n' &&
                buf[pos + 2] == '\r' && buf[pos + 3] == '\n') { hsz = (int)pos + 4; break; }
        }
        if (hsz < 0) {
            if (c->rlen >= MAX_HEADER_SIZE) {
                http_send_json_response(http, c, 431, "{\"error\":\"Request header too large\"}");
                http_update_status_stats(http, 431);
                return -1;
            }
            continue;
        }
        if ((size_t)hsz > MAX_HEADER_SIZE) {
            http_send_json_response(http, c, 431, "{\"error\":\"Request header too large\"}");
            http_update_status_stats(http, 431);
            return -1;
        }

        long long clen = 0;
        for (size_t j = 0; j + 15 <= (size_t)hsz; j++) {
            if (_strnicmp(buf + j, "Content-Length:", 15) == 0) {
                const char *cp = buf + j + 15;
                while (*cp == ' ' || *cp == '\t') cp++;
                clen = http_parse_decimal(cp, buf + c->rlen);
                break;
            }
        }
        if (clen < 0) clen = 0;

        /* Effective body cap: config limit, or a hard 256 MB safety cap when
         * max_body_mb is 0 (unlimited). A lying Content-Length must not be
         * able to force a giant allocation per connection. */
        size_t max_body = http_max_body_bytes(http);
        if (max_body == (size_t)-1) max_body = HTTP_HARD_MAX_BODY;
        if ((size_t)clen > max_body) {
            http_send_json_response(http, c, 413, "{\"error\":\"Request body too large\"}");
            http_update_status_stats(http, 413);
            return -1;
        }
        rd_deadline = rd_start + io_eff * 12 + 1000 +
                      (unsigned long)((unsigned long long)clen / 10000UL) * 1000UL;
        size_t need = (size_t)hsz + (size_t)clen;
        if (need > max_body + MAX_HEADER_SIZE) {
            http_send_json_response(http, c, 413, "{\"error\":\"Request body too large\"}");
            http_update_status_stats(http, 413);
            return -1;
        }
        if (need > sizeof(c->rb) && !c->big) {
            c->big_cap = need + 1;
            c->big = (char *)malloc(c->big_cap);
            if (!c->big) {
                http_send_json_response(http, c, 500, "{\"error\":\"Out of memory\"}");
                http_update_status_stats(http, 500);
                return -1;
            }
            memcpy(c->big, c->rb, c->rlen);
        }
        if (c->rlen >= need) return 0;
        if (need > (c->big ? c->big_cap : sizeof(c->rb))) return -1;
    }
}

// Serve a single accepted connection in a worker thread
static void http_serve_conn(http_server_t *http, http_ctx_t *c) {
    if (c->is_https && c->_ssl) {
        if (SSL_accept((SSL *)c->_ssl) != 0) {
            return;
        }
        c->handshake_state = 1;
    }
    if (http_conn_read_request(http, c) != 0) { http_send_buf(http, c); return; }
    c->req_done = 1; /* request fully read - the reaper must not touch it
                       (the client is allowed to stay silent while it
                       receives the response) */
    http_do_parse(http, c, c->rb, c->rlen);
    http_send_buf(http, c);
}

// Accept loop: accepts new connections; select is used for shutdown checks
static int http_accept_loop(http_server_t *http) {
    #ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[accept_loop] listening on port %d (blocking I/O)\n", http->port);
#endif
    while (!http->shutdown) {
        fd_set rf; FD_ZERO(&rf); FD_SET(http->listen_fd, &rf);
        struct timeval tv;
        if (http->timeout_accept_ms <= 0) {
            if (select((int)http->listen_fd + 1, &rf, NULL, NULL, NULL) < 0) { if (http->shutdown) break; continue; }
        } else {
            tv.tv_sec = http->timeout_accept_ms / 1000;
            tv.tv_usec = (http->timeout_accept_ms % 1000) * 1000;
            int sel = select((int)http->listen_fd + 1, &rf, NULL, NULL, &tv);
            if (sel < 0) { if (http->shutdown) break; continue; }
            if (sel == 0) continue;
        }
        if (!FD_ISSET(http->listen_fd, &rf)) continue;

        struct sockaddr_in sa; int slen = sizeof(sa);
        SOCKET sock = accept(http->listen_fd, (struct sockaddr *)&sa, &slen);
        if (sock == INVALID_SOCKET) continue;

        /* Bound every blocking recv()/send() on this connection. The TLS
         * layer (ssl_sock_read/ssl_sock_write) uses raw blocking I/O;
         * without SO_RCVTIMEO/SO_SNDTIMEO a stalled client pins the worker
         * thread forever. Half the io_timeout: ssl_sock_read() retries the
         * timed-out recv() once, so total wait stays within io_timeout. */
        http_sock_set_io_timeout(sock, (http->timeout_io_ms > 0) ? http->timeout_io_ms / 2 : 0);

        int is_tls = 0;
        if (http->ssl_use) {
            int have_data = http_sock_poll(sock, 0) > 0;
            if (have_data) {
                unsigned char probe;
                int pr = recv(sock, (char *)&probe, 1, MSG_PEEK);
                if (pr == 1 && probe == 0x16) is_tls = 1;
            } else {
                is_tls = 1;
            }
            if (have_data && !is_tls) {
                char r426[512]; int hl426 = snprintf(r426, sizeof(r426),
                    "HTTP/1.0 426 Upgrade Required\r\nServer: %s\r\n\r\n",
                    (http->server_name && http->server_name[0]) ? http->server_name : DEF_SERVER_NAME);
                http_sock_send_all(sock, r426, hl426, http->timeout_io_ms);
                shutdown(sock, SD_SEND);
                unsigned long drain_start = compat_tick();
                for (;;) {
                    if (http->timeout_io_ms > 0 &&
                        compat_tick() - drain_start > (unsigned long)http->timeout_io_ms) break;
                    fd_set rd; FD_ZERO(&rd); FD_SET(sock, &rd);
                    struct timeval t = { 0, 20000 };
                    if (select((int)sock + 1, &rd, NULL, NULL, &t) <= 0) break;
                    char tmp[4096];
                    int n = recv(sock, tmp, sizeof(tmp), 0);
                    if (n <= 0) break;
                }
                shutdown(sock, SD_BOTH);
                closesocket(sock);
                continue;
            }
        }

        http_ctx_t *c = http_ctx_alloc(http, sock, is_tls);
        if (!c) { shutdown(sock, SD_BOTH); closesocket(sock); continue; }
        if (is_tls) {
            SSL *ssl = SSL_new(http->ssl_ctx);
            if (!ssl) { http_conn_close(http, c); continue; }
            SSL_set_fd(ssl, (int)sock);
            c->_ssl = ssl;
        }
        http_p_push(http, c);
    }
    return 0;
}

// Start the server accept loop and thread pool
int http_run(http_server_t *http, HttpLogFn log) {
    if (!http) return -1;
    http->log_fn = log;
    if (http->ssl_use) {
        if (http_setup_https(http, http->cert_file, http->key_file) != 0) {
#ifndef HTTP_NO_LOG
            if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_WARN, "[warn] HTTPS setup failed, running HTTP only\n");
#endif
            http->ssl_use = 0;
        }
    }
    http->running = 1;
    http->listen_fd = http_setup(http->port);
    if (http->listen_fd == INVALID_SOCKET) {
#ifndef HTTP_NO_LOG
        if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_ERROR, "[err] start failed\n");
#endif
        return -1;
    }
#ifndef HTTP_NO_LOG
    if (http->log_fn) http->log_fn(HTTP_LOG_LEVEL_INFO, "[listen] port=%d\n", http->port);
#endif
    int qs = http->max_clients > 0 ? http->max_clients : MAX_CLIENTS;
    if (qs > MAX_CLIENTS) qs = MAX_CLIENTS;
    http_p_start(http, http->worker_threads, qs);
    if (thr_create(&http->reaper, http_reaper, http) == 0) http->reaper_on = 1;
    http_accept_loop(http);
    return 0;
}

// Initialize query string parser structure
void http_query_init(http_query_string_t *qs) {
    memset(qs, 0, sizeof(http_query_string_t));
    qs->capacity = HTTP_MAX_QUERY_INITIAL;
    qs->params = (http_query_param_t *)calloc((size_t)qs->capacity, sizeof(http_query_param_t));
}

// Free query string parser resources
void http_query_destroy(http_query_string_t *qs) {
    if (qs->params) {
        for (int i = 0; i < qs->count; i++) { free(qs->params[i].key); free(qs->params[i].value); }
        free(qs->params); qs->params = NULL;
    }
    qs->count = 0; qs->capacity = 0;
}

// Parse URL query string into key-value pairs
int http_query_parse(http_query_string_t *qs, const char *query_string) {
    if (!query_string || !*query_string) return 0;
    size_t slen = strlen(query_string);
    char *buf = (char *)malloc(slen + 1);
    if (!buf) return 0;
    memcpy(buf, query_string, slen + 1);
    char *saveptr = NULL;
    char *tok = strtok_s(buf, "&", &saveptr);
    while (tok) {
        char *eq = strchr(tok, '=');
        if (eq) {
            *eq = '\0';
            const char *val_str = eq + 1;
            if (qs->count >= qs->capacity) {
                int new_cap = qs->capacity * 2;
                http_query_param_t *new_p = (http_query_param_t *)realloc(qs->params, (size_t)new_cap * sizeof(http_query_param_t));
                if (!new_p) { free(buf); return qs->count; }
                memset((char *)new_p + qs->capacity * sizeof(http_query_param_t), 0, (size_t)(new_cap - qs->capacity) * sizeof(http_query_param_t));
                qs->params = new_p; qs->capacity = new_cap;
            }
            qs->params[qs->count].key = http_url_decode_alloc(tok, strlen(tok));
            qs->params[qs->count].value = http_url_decode_alloc(val_str, strlen(val_str));
            if (qs->params[qs->count].key && qs->params[qs->count].value) qs->count++;
            else { free(qs->params[qs->count].key); free(qs->params[qs->count].value); }
        } else {
            if (qs->count >= qs->capacity) {
                int new_cap = qs->capacity * 2;
                http_query_param_t *new_p = (http_query_param_t *)realloc(qs->params, (size_t)new_cap * sizeof(http_query_param_t));
                if (!new_p) { free(buf); return qs->count; }
                memset((char *)new_p + qs->capacity * sizeof(http_query_param_t), 0, (size_t)(new_cap - qs->capacity) * sizeof(http_query_param_t));
                qs->params = new_p; qs->capacity = new_cap;
            }
            qs->params[qs->count].key = http_url_decode_alloc(tok, strlen(tok));
            qs->params[qs->count].value = (char *)"";
            if (qs->params[qs->count].key) qs->count++;
            else free(qs->params[qs->count].key);
        }
        tok = strtok_s(NULL, "&", &saveptr);
    }
    free(buf);
    return qs->count;
}

// Get value by key from parsed query string
const char *http_query_get(const http_query_string_t *qs, const char *key) {
    for (int i = 0; i < qs->count; i++) {
        if (qs->params[i].key && strcmp(qs->params[i].key, key) == 0) return qs->params[i].value;
    }
    return NULL;
}

// Check if key exists in parsed query string
int http_query_has(const http_query_string_t *qs, const char *key) {
    return http_query_get(qs, key) != NULL;
}

// Parse multipart/form-data body into fields
int http_multipart_parse(http_multipart_form_t *form, const char *body, size_t body_len, const char *boundary) {
    memset(form, 0, sizeof(http_multipart_form_t));
    form->capacity = HTTP_MAX_MPART_INITIAL;
    form->fields = (http_multipart_field_t *)calloc((size_t)form->capacity, sizeof(http_multipart_field_t));
    char delim[512], closing[512], nxt[520];
    int dl = snprintf(delim, sizeof(delim), "--%s", boundary);
    int cl = snprintf(closing, sizeof(closing), "--%s--", boundary);
    int nl = snprintf(nxt, sizeof(nxt), "\r\n--%s", boundary);
    const char *end = body + body_len;
    const char *pos = http_memmem(body, body_len, delim, (size_t)dl);
    if (!pos) { free(form->fields); form->fields = NULL; return 0; }
    while (pos && (size_t)(end - pos) > 0) {
        if (strncmp(pos, closing, (size_t)cl) == 0) break;
        const char *crlf = http_memmem(pos, (size_t)(end - pos), "\r\n", 2);
        if (!crlf) break;
        pos = crlf + 2;
        const char *next_b = http_memmem(pos, (size_t)(end - pos), nxt, (size_t)nl);
        if (!next_b) break;
        const char *bnd_start = next_b + 2;
        if (strlen(bnd_start) < strlen(delim) || strncmp(bnd_start, delim, (size_t)dl) != 0) break;
        const char *hdr_end = http_memmem(pos, (size_t)(next_b - pos), "\r\n\r\n", 4);
        if (!hdr_end) break;
        size_t hdr_len = (size_t)(hdr_end - pos);
        if (hdr_len >= 8192) break;
        char headers[8192];
        memcpy(headers, pos, hdr_len); headers[hdr_len] = '\0';
        char *disp_name = NULL, *disp_file = NULL;
        const char *cd = http_strcasestr_custom(headers, "Content-Disposition:");
        if (cd) http_parse_content_disposition(cd, &disp_name, &disp_file);
        const char *ct_hdr = http_strcasestr_custom(headers, "Content-Type:");
        char *content_type = NULL;
        if (ct_hdr) content_type = http_extract_header_value(ct_hdr + 17, "");
        const char *data_start = hdr_end + 4;
        size_t data_len = (size_t)(next_b - data_start);
        while (data_len > 0 && (data_start[data_len - 1] == '\r' || data_start[data_len - 1] == '\n')) data_len--;
        if (disp_name) {
            if (form->count >= form->capacity) {
                int nc = form->capacity * 2;
                http_multipart_field_t *nf = (http_multipart_field_t *)realloc(form->fields, (size_t)nc * sizeof(http_multipart_field_t));
                if (!nf) break;
                memset((char *)nf + form->capacity * sizeof(http_multipart_field_t), 0, (size_t)(nc - form->capacity) * sizeof(http_multipart_field_t));
                form->fields = nf; form->capacity = nc;
            }
            http_multipart_field_t *f = &form->fields[form->count];
            f->name = disp_name; f->filename = disp_file; f->content_type = content_type;
            f->data = (void *)malloc((size_t)data_len + 1);
            memcpy(f->data, data_start, data_len); ((char *)f->data)[data_len] = '\0';
            f->data_len = data_len; form->count++;
        } else { free(disp_name); free(disp_file); free(content_type); }
        if ((size_t)(end - bnd_start) <= (size_t)cl || strncmp(bnd_start, closing, (size_t)cl) == 0) break;
        pos = bnd_start;
    }
    return form->count;
}

// Free multipart form resources
void http_multipart_destroy(http_multipart_form_t *form) {
    if (form->fields) {
        for (int i = 0; i < form->count; i++) {
            free((void *)form->fields[i].name); free((void *)form->fields[i].filename);
            free((void *)form->fields[i].content_type); free(form->fields[i].data);
        }
        free(form->fields); form->fields = NULL;
    }
    form->count = 0;
}

// Get field by name from parsed form
const http_multipart_field_t *http_multipart_get(const http_multipart_form_t *form, const char *name) {
    for (int i = 0; i < form->count; i++) {
        if (form->fields[i].name && strcmp(form->fields[i].name, name) == 0) return &form->fields[i];
    }
    return NULL;
}

// Check if field is a file upload
int http_multipart_is_file(const http_multipart_field_t *f) {
    return f && f->filename != NULL && f->filename[0] != '\0';
}

// Perform WebSocket upgrade handshake
int http_ws_handshake(http_ctx_t *c, const char *raw_hdr, size_t hdr_len) {
    char key_buf[256] = {0}, accept_buf[32] = {0};
    const char *key_line = http_strcasestr_custom(raw_hdr, "Sec-WebSocket-Key:");
    if (!key_line) return 0;
    key_line += strlen("Sec-WebSocket-Key:");
    while (*key_line == ':' || *key_line == ' ') key_line++;
    size_t klen = 0;
    const char *kl_end = key_line;
    while (kl_end < raw_hdr + hdr_len && *kl_end != '\r' && *kl_end != '\n' && klen < 255) { kl_end++; klen++; }
    if (klen == 0 || klen >= 256) return 0;
    memcpy(key_buf, key_line, klen);
    unsigned char combined[512];
    size_t combined_len = klen + strlen(http_ws_guid);
    memcpy(combined, key_buf, klen);
    memcpy(combined + klen, http_ws_guid, strlen(http_ws_guid));
    unsigned char digest[20];
    http_sha1(combined, combined_len, digest);
    http_base64_encode(digest, 20, accept_buf);
    const char *resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n";
    char response[512];
    int rlen = snprintf(response, sizeof(response), resp, accept_buf);
    resp_send(c, response, (size_t)rlen);
    return 1;
}

// Write WebSocket frame header bytes (server frames are unmasked)
void http_ws_write_frame_header(http_ctx_t *c, unsigned char fin, unsigned char opcode, uint64_t payload_len) {
    unsigned char header[14];
    int hlen = 2;
    header[0] = (unsigned char)(0x80 | opcode);
    if (payload_len <= 125) { header[1] = (unsigned char)payload_len; hlen = 2; }
    else if (payload_len <= 0xFFFF) { header[1] = 126; uint16_t plen = (uint16_t)payload_len; memcpy(header + 2, &plen, 2); hlen = 4; }
    else { header[1] = 127; memcpy(header + 2, &payload_len, 8); hlen = 10; }
    resp_send(c, header, (size_t)hlen);
}

// Send WebSocket text frame
void http_ws_send_text(http_ctx_t *c, const char *text) {
    size_t len = strlen(text);
    http_ws_write_frame_header(c, 1, HTTP_WS_OPCODE_TEXT, len);
    if (len > 0) resp_send(c, text, len);
}

// Send WebSocket binary frame
void http_ws_send_binary(http_ctx_t *c, const unsigned char *data, size_t len) {
    http_ws_write_frame_header(c, 1, HTTP_WS_OPCODE_BINARY, len);
    if (len > 0) resp_send(c, data, len);
}

// Send WebSocket close frame
void http_ws_send_close(http_ctx_t *c, int code, const char *reason) {
    unsigned char msg[256];
    size_t ml = 0;
    uint16_t ccode = (uint16_t)code;
    memcpy(msg + ml, &ccode, 2); ml += 2;
    if (reason && reason[0]) { size_t rlen = strlen(reason); if (ml + rlen < sizeof(msg)) { memcpy(msg + ml, reason, rlen); ml += rlen; } }
    http_ws_write_frame_header(c, 1, HTTP_WS_OPCODE_CLOSE, ml);
    if (ml > 0) resp_send(c, msg, ml);
}

// Send a WebSocket pong frame echoing the given payload
void http_ws_send_pong(http_ctx_t *c, const unsigned char *payload, size_t len) {
    http_ws_write_frame_header(c, 1, HTTP_WS_OPCODE_PONG, len);
    if (len > 0) resp_send(c, payload, len);
}

// Parse incoming WebSocket frame
int http_ws_read_frame(SOCKET fd, unsigned char *rb, size_t rlen, size_t off, http_ws_frame_t *frame) {
    (void)fd;
    if (rlen - off < 2) return 0;
    unsigned char *buf = rb + off;
    unsigned char first = buf[0], second = buf[1];
    unsigned char opcode = first & 0x0F;
    int is_masked = (second & 0x80) ? 1 : 0;
    uint64_t payload_len = second & 0x7F;
    size_t header_ext_len = 2;   // base header is always present
    if (payload_len == 126) {
        if (rlen - off < 4) return 0;
        payload_len = (uint64_t)(((uint16_t)buf[2] << 8) | buf[3]);
        header_ext_len = 4;
    } else if (payload_len == 127) {
        if (rlen - off < 10) return 0;
        payload_len = 0;
        for (int k = 0; k < 8; k++) payload_len = (payload_len << 8) | buf[2 + k];
        header_ext_len = 10;
    }
    if (!is_masked && opcode != HTTP_WS_OPCODE_CLOSE) return 0;
    size_t mask_off = header_ext_len + (is_masked ? 4 : 0);
    if (rlen - off < mask_off + payload_len) return 0;
    frame->is_masked = is_masked;
    frame->payload_len = payload_len;
    frame->payload_len_total = payload_len;
    frame->payload = rb + off + mask_off;
    if (is_masked) {
        for (uint64_t i = 0; i < payload_len; i++) frame->payload[i] ^= rb[off + header_ext_len + (i % 4)];
    }
    return (int)(mask_off + payload_len);
}

// Send SSE response headers
void http_sse_init_response(http_ctx_t *c) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
    resp_send(c, h, strlen(h));
}

// Send SSE event to client
void http_sse_send(http_ctx_t *c, const char *event, const char *data, const char *id, const char *retry) {
    (void)retry;
    char chunk[4096];
    int off = 0, total = sizeof(chunk);
    #define SSE_ADD(fmt, ...) do { off += snprintf(chunk + off, (size_t)(total - off), fmt, ##__VA_ARGS__); } while(0)
    SSE_ADD("retry: 3000\r\n");
    if (id) SSE_ADD("id: %s\r\n", id);
    if (event && event[0]) SSE_ADD("event: %s\r\n", event);
    const char *data_line = data;
    while (data_line && data_line[0]) {
        const char *nl = strchr(data_line, '\n');
        if (nl) { SSE_ADD("data: %.*s\r\n", (int)(nl - data_line), data_line); data_line = nl + 1; }
        else { SSE_ADD("data: %s\r\n", data_line); break; }
    }
    SSE_ADD("\r\n");
    resp_send(c, chunk, (size_t)off);
}

// Compare HTTP method with pattern
int http_method_matches(const char *pattern, const char *method) {
    if (!pattern || pattern[0] == '\0') return 1;
    return _stricmp(pattern, method) == 0;
}