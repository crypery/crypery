/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * url.c - self-contained HTTP/HTTPS client library.
 *
 * A curl-like client library built on the bundled TLS stack (ssl.c + tls.c).
 * Provides URL parsing, HTTP/1.1 requests, chunked transfer decoding,
 * multipart form bodies, redirect handling and the transport (socket/TLS)
 * layer. It does NOT parse command-line arguments; the application maps its
 * options onto a UrlCtx and drives the request with url_run().
 *
 * No external libraries are used besides the bundled ssl.c / tls.c and the
 * standard C library + sockets.
 *
 * Portability: the transport uses Winsock on Windows (#ifdef _WIN32) and
 * BSD sockets on POSIX systems. All platform-specific bits (socket type,
 * error codes, non-blocking mode, sleeps, tick counter, case-insensitive
 * string compare) are isolated in the portability section below.
 *
 * All public functions are prefixed with url_; their full documentation
 * (parameters and return values) is in url.h. Each function, structure and
 * constant below carries a short one-line description. The public context
 * structure is UrlCtx, created with url_init() and freed with url_free().
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "url.h"
#include "ssl.h"
#include "tls.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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
#include <fcntl.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>
#endif

// ---- portability shims: Winsock on Windows, BSD sockets on POSIX ----
#ifdef _WIN32
#define net_err()      WSAGetLastError()
#define NET_CONNRESET  WSAECONNRESET
#define NET_TIMEDOUT   WSAETIMEDOUT
#define NET_INPROGRESS WSAEWOULDBLOCK
#else
#define SOCKET         int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define net_err()      errno
#define NET_CONNRESET  ECONNRESET
#define NET_TIMEDOUT   EAGAIN
#define NET_INPROGRESS EINPROGRESS
#define closesocket    close
#define ioctlsocket    ioctl
#define SD_BOTH        SHUT_RDWR
#define _stricmp       strcasecmp
#define _strnicmp      strncasecmp
#endif

#ifdef _WIN32
#define x_strdup _strdup
#else
#define x_strdup strdup
#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif

// Toggle non-blocking mode on a socket (portable FIONBIO / O_NONBLOCK)
static int set_nonblocking(SOCKET s, int on) {
#ifdef _WIN32
    u_long mode = on ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
#endif
}

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

// Growable byte buffer used to build request/response strings
typedef struct {
    char *s;
    size_t len;
    size_t cap;
} StrBuf;

// Initialize a growable string buffer
static void sb_init(StrBuf *b) { b->s = NULL; b->len = 0; b->cap = 0; }
// Free a growable string buffer
static void sb_free(StrBuf *b) { free(b->s); b->s = NULL; b->len = b->cap = 0; }

// Reserve additional space in a growable string buffer
static void sb_reserve(StrBuf *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return;
    size_t ncap = b->cap ? b->cap * 2 : 256;
    while (ncap < b->len + extra + 1) ncap *= 2;
    b->s = (char *)realloc(b->s, ncap);
    b->cap = ncap;
}

// Append data to a growable string buffer
static void sb_append(StrBuf *b, const char *data, size_t len) {
    sb_reserve(b, len);
    memcpy(b->s + b->len, data, len);
    b->len += len;
    b->s[b->len] = '\0';
}

static void sb_appends(StrBuf *b, const char *s) { sb_append(b, s, strlen(s)); }
static void sb_appendc(StrBuf *b, char c) { sb_append(b, &c, 1); }

/*
 * Write the decimal representation of v (sign handled by neg) into buf.
 * Returns buf (NUL-terminated); buf must hold at least 24 bytes.
 */
static char *u_itoa_buf(unsigned long long v, int neg, char *buf) {
    char tmp[24];
    int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v > 0) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    char *p = buf;
    if (neg) *p++ = '-';
    while (n > 0) *p++ = tmp[--n];
    *p = '\0';
    return buf;
}

// Bounded string copy: write at most size-1 characters plus a NUL terminator.
static void u_strcpyz(char *out, size_t size, const char *s) {
    size_t i = 0;
    if (size == 0) return;
    while (s[i] && i + 1 < size) { out[i] = s[i]; i++; }
    out[i] = '\0';
}

// Bounded string append onto an existing NUL-terminated buffer.
static void u_strcat(char *out, size_t size, const char *s) {
    size_t i = 0;
    if (size == 0) return;
    while (out[i] && i + 1 < size) i++;
    size_t k = 0;
    while (s[k] && i + 1 < size) out[i++] = s[k++];
    out[i] = '\0';
}

// Append the decimal representation of an int to a fixed buffer.
static void u_strcat_int(char *out, size_t size, int v) {
    unsigned int uv = v < 0 ? (unsigned int)(-(v + 1)) + 1u : (unsigned int)v;
    char tmp[24];
    u_strcat(out, size, u_itoa_buf(uv, v < 0, tmp));
}

// Append the decimal representation of a size_t to a fixed buffer.
static void u_strcat_size(char *out, size_t size, size_t v) {
    char tmp[24];
    u_strcat(out, size, u_itoa_buf((unsigned long long)v, 0, tmp));
}

// Append the decimal representation of an int to a growable buffer.
static void sb_append_int(StrBuf *b, int v) {
    unsigned int uv = v < 0 ? (unsigned int)(-(v + 1)) + 1u : (unsigned int)v;
    char tmp[24];
    sb_appends(b, u_itoa_buf(uv, v < 0, tmp));
}

// Append the decimal representation of a size_t to a growable buffer.
static void sb_append_size(StrBuf *b, size_t v) {
    char tmp[24];
    sb_appends(b, u_itoa_buf((unsigned long long)v, 0, tmp));
}

/*
 * Read a file into a growable buffer using native OS APIs (no stdio).
 * Returns 0 on success, -1 if the file could not be opened.
 */
static int sb_read_file(StrBuf *b, const char *path) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    char buf[8192];
    DWORD r;
    while (ReadFile(h, buf, sizeof(buf), &r, NULL) && r > 0) sb_append(b, buf, r);
    CloseHandle(h);
    return 0;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[8192];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) sb_append(b, buf, (size_t)r);
    close(fd);
    return 0;
#endif
}

// Add or update a header in a header list
void url_header_add(HeaderList *l, const char *name, const char *value) {
    char n[64];
    int w = 0;
    for (const char *p = name; *p && w < (int)sizeof(n) - 1; p++) {
        if (*p == ' ' || *p == '\t') continue;
        n[w++] = (char)tolower((unsigned char)*p);
    }
    n[w] = '\0';

    const char *v = value;
    while (*v == ' ' || *v == '\t') v++;
    size_t vl = strlen(v);
    while (vl > 0 && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;

    for (int i = 0; i < l->n; i++) {
        if (strcmp(l->h[i].name, n) == 0) {
            size_t cl = vl < sizeof(l->h[i].value) - 1 ? vl : sizeof(l->h[i].value) - 1;
            memcpy(l->h[i].value, v, cl);
            l->h[i].value[cl] = '\0';
            return;
        }
    }
    if (l->n >= URL_MAX_HEADERS) return;
    Header *h = &l->h[l->n++];
    strcpy(h->name, n);
    size_t cl = vl < sizeof(h->value) - 1 ? vl : sizeof(h->value) - 1;
    memcpy(h->value, v, cl);
    h->value[cl] = '\0';
}

const char *url_header_get(const HeaderList *l, const char *name) {
    for (int i = 0; i < l->n; i++)
        if (_stricmp(l->h[i].name, name) == 0) return l->h[i].value;
    return NULL;
}

// Extract scheme from URL and set is_ssl flag, returns scheme length
static int url_scheme_len(const char *url, int *is_ssl) {
    if (_strnicmp(url, "https://", 8) == 0) { *is_ssl = 1; return 8; }
    if (_strnicmp(url, "http://", 7) == 0)  { *is_ssl = 0; return 7; }
    return -1;
}

// Parse a URL into UrlInfo structure
int url_parse(const char *url, UrlInfo *u) {
    memset(u, 0, sizeof *u);

    int is_ssl;
    int slen = url_scheme_len(url, &is_ssl);
    if (slen < 0) return -1;
    u->is_ssl = is_ssl;
    u->port = is_ssl ? 443 : 80;

    const char *p = url + slen;

    // Strip userinfo up to the last '@' in the authority part.
    const char *auth_end = p;
    while (*auth_end && *auth_end != '/') auth_end++;
    const char *at = NULL;
    for (const char *q = p; q < auth_end; q++) if (*q == '@') at = q;
    if (at) p = at + 1;

    // Authority: host[:port], possibly an [IPv6] literal.
    const char *authority_end = auth_end;
    if (*p == '[') {
        const char *br = strchr(p, ']');
        if (!br || br >= authority_end) return -1;
        size_t hlen = (size_t)(br - p - 1);
        if (hlen <= 0 || hlen >= sizeof(u->host)) return -1;
        memcpy(u->host, p + 1, hlen);
        u->host[hlen] = '\0';
        p = br + 1;
        if (*p == ':' && p + 1 < authority_end) {
            char ps[16];
            size_t plen = (size_t)(authority_end - p - 1);
            if (plen <= 0 || plen >= sizeof(ps)) return -1;
            memcpy(ps, p + 1, plen);
            ps[plen] = '\0';
            long prt = strtol(ps, NULL, 10);
            if (prt <= 0 || prt > 65535) return -1;
            u->port = (int)prt;
        }
    } else {
        const char *colon = memchr(p, ':', (size_t)(authority_end - p));
        size_t hlen;
        if (colon) hlen = (size_t)(colon - p);
        else       hlen = (size_t)(authority_end - p);
        if (hlen <= 0 || hlen >= sizeof(u->host)) return -1;
        memcpy(u->host, p, hlen);
        u->host[hlen] = '\0';
        if (colon) {
            char ps[16];
            size_t plen = (size_t)(authority_end - colon - 1);
            if (plen <= 0 || plen >= sizeof(ps)) return -1;
            memcpy(ps, colon + 1, plen);
            ps[plen] = '\0';
            long prt = strtol(ps, NULL, 10);
            if (prt <= 0 || prt > 65535) return -1;
            u->port = (int)prt;
        }
    }

    // Path (and query); strip any fragment.
    if (*auth_end == '/') {
        size_t plen = strlen(auth_end);
        const char *frag = strchr(auth_end, '#');
        if (frag) plen = (size_t)(frag - auth_end);
        if (plen >= sizeof(u->path)) return -1;
        memcpy(u->path, auth_end, plen);
        u->path[plen] = '\0';
    } else {
        u_strcpyz(u->path, sizeof(u->path), "/");
    }
    return 0;
}

// Decode URL-encoded string in place
void url_decode(char *s) {
    char *r = s;
    while (*s) {
        if (s[0] == '%' && s[1] && s[2]) {
            char hb[3] = { s[1], s[2], 0 };
            *r++ = (char)strtol(hb, NULL, 16);
            s += 3;
        } else {
            *r++ = *s++;
        }
    }
    *r = '\0';
}

void url_normalize_path(const char *path, char *out, size_t outlen) {
    char tmp[URL_MAX_PATH + 512];
    char tailbuf[URL_MAX_PATH];
    const char *seg[256];
    size_t seglen[256];
    int n = 0, absolute, i;
    size_t o = 0, tl;
    const char *p;

    if (!path) {
        if (outlen) out[0] = '\0';
        return;
    }
    tailbuf[0] = '\0';
    tl = strlen(path);
    if (tl >= sizeof(tmp)) tl = sizeof(tmp) - 1;
    memcpy(tmp, path, tl);
    tmp[tl] = '\0';

    /* split off query / fragment */
    {
        char *q = strpbrk(tmp, "?#");
        if (q) {
            size_t ql = strlen(q);
            if (ql >= sizeof(tailbuf)) ql = sizeof(tailbuf) - 1;
            memcpy(tailbuf, q, ql);
            tailbuf[ql] = '\0';
            *q = '\0';
        }
    }
    absolute = (tmp[0] == '/');
    p = tmp;
    while (*p) {
        const char *e;
        size_t l;
        while (*p == '/') p++;
        if (!*p) break;
        e = p;
        while (*e && *e != '/') e++;
        l = (size_t)(e - p);
        if (l == 1 && p[0] == '.') {
            /* current directory: drop */
        } else if (l == 2 && p[0] == '.' && p[1] == '.') {
            if (n > 0) n--;
        } else if (n < 256) {
            seg[n] = p;
            seglen[n] = l;
            n++;
        }
        p = e;
    }
    if (absolute && o + 1 < outlen) out[o++] = '/';
    for (i = 0; i < n; i++) {
        if (i > 0 && o + 1 < outlen) out[o++] = '/';
        if (o + seglen[i] < outlen) {
            memcpy(out + o, seg[i], seglen[i]);
            o += seglen[i];
        }
    }
    if (outlen == 0) return;
    if (o >= outlen) o = outlen - 1;
    out[o] = '\0';
    if (tailbuf[0] && o + 1 < outlen)
        strncat(out, tailbuf, outlen - o - 1);
}

void url_join(const char *base, const char *loc, char *out, size_t outlen) {
    if (_strnicmp(loc, "https://", 8) == 0 || _strnicmp(loc, "http://", 7) == 0) {
        u_strcpyz(out, outlen, loc);
        return;
    }

    char scheme[16] = "http";
    const char *b = base;
    if (_strnicmp(b, "https://", 8) == 0) { strcpy(scheme, "https"); b += 8; }
    else if (_strnicmp(b, "http://", 7) == 0) { strcpy(scheme, "http"); b += 7; }

    const char *slash = strchr(b, '/');
    size_t alen = slash ? (size_t)(slash - b) : strlen(b);
    char auth[URL_MAX_HOST + 32];
    if (alen >= sizeof(auth)) alen = sizeof(auth) - 1;
    memcpy(auth, b, alen);
    auth[alen] = '\0';

    if (strncmp(loc, "//", 2) == 0) {
        u_strcpyz(out, outlen, scheme);
        u_strcat(out, outlen, ":");
        u_strcat(out, outlen, loc);
        return;
    }
    if (loc[0] == '/') {
        char norm[URL_MAX_PATH];
        url_normalize_path(loc, norm, sizeof(norm));
        u_strcpyz(out, outlen, scheme);
        u_strcat(out, outlen, "://");
        u_strcat(out, outlen, auth);
        u_strcat(out, outlen, norm);
        return;
    }

    char dir[URL_MAX_PATH];
    if (slash && strrchr(slash, '/')) {
        const char *last = strrchr(slash, '/');
        size_t dlen = (size_t)(last - slash + 1);
        if (dlen >= sizeof(dir)) dlen = sizeof(dir) - 1;
        memcpy(dir, slash, dlen);
        dir[dlen] = '\0';
    } else {
        strcpy(dir, "/");
    }
    {
        char raw[URL_MAX_PATH * 2];
        char norm[URL_MAX_PATH];
        snprintf(raw, sizeof(raw), "%s%s", dir, loc);
        url_normalize_path(raw, norm, sizeof(norm));
        u_strcpyz(out, outlen, scheme);
        u_strcat(out, outlen, "://");
        u_strcat(out, outlen, auth);
        u_strcat(out, outlen, norm);
    }
}

// Extract filename from Content-Disposition header
int url_content_disposition_filename(const char *cd, char *out, size_t outlen) {
    const char *p = NULL;
    const char *q = cd;
    while (*q) {
        if (tolower((unsigned char)q[0]) == 'f' && _strnicmp(q, "filename=", 9) == 0) {
            p = q;
            break;
        }
        q++;
    }
    if (!p) return -1;
    p += 9;
    if (*p == '*') {
        const char *q = strstr(p, "''");
        if (q) p = q + 2;
    }
    size_t w = 0;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && w + 1 < outlen) out[w++] = *p++;
        out[w] = '\0';
        return w > 0 ? 0 : -1;
    }
    while (*p && *p != ';' && *p != ' ' && *p != '\t' && w + 1 < outlen) out[w++] = *p++;
    out[w] = '\0';
    return w > 0 ? 0 : -1;
}

// Get remote filename from URL path or Content-Disposition header
int url_remote_name(const UrlInfo *u, const char *disposition, char *out, size_t outlen) {
    if (disposition && url_content_disposition_filename(disposition, out, outlen) == 0)
        return 0;

    const char *path = u->path;
    const char *seg = strrchr(path, '/');
    const char *start = seg ? seg + 1 : path;
    char tmp[URL_MAX_PATH];
    size_t tl = strlen(start);
    if (tl >= sizeof(tmp)) tl = sizeof(tmp) - 1;
    memcpy(tmp, start, tl);
    tmp[tl] = '\0';
    char *q = strchr(tmp, '?');
    if (q) *q = '\0';
    if (tmp[0] == '\0') {
        u_strcpyz(out, outlen, "index.html");
        return 0;
    }
    url_decode(tmp);
    u_strcpyz(out, outlen, tmp);
    return 0;
}

// Parse HTTP status line and headers from raw response data
int url_http_parse_status_and_headers(const char *raw, size_t rawlen, ResponseHead *rh) {
    memset(rh, 0, sizeof *rh);
    size_t pos = 0;
    int first = 1;

    while (pos < rawlen) {
        const char *nl = memchr(raw + pos, '\n', rawlen - pos);
        size_t llen = nl ? (size_t)(nl - (raw + pos)) : rawlen - pos;
        if (llen > 0 && raw[pos + llen - 1] == '\r') llen--;
        char line[8192];
        size_t cplen = llen < sizeof(line) - 1 ? llen : sizeof(line) - 1;
        memcpy(line, raw + pos, cplen);
        line[cplen] = '\0';
        if (nl) pos = (size_t)(nl - raw) + 1;
        else pos = rawlen;
        if (line[0] == '\0') break;

        if (first) {
            first = 0;
            if (strncmp(line, "HTTP/", 5) != 0) return -1;
            char *p = line + 5;
            char *sp = strchr(p, ' ');
            if (!sp) return -1;
            size_t vlen = (size_t)(sp - p);
            if (vlen == 0) return -1;
            if (vlen >= sizeof(rh->version)) vlen = sizeof(rh->version) - 1;
            memcpy(rh->version, p, vlen);
            rh->version[vlen] = '\0';
            while (*sp == ' ') sp++;
            char *code = sp;
            while (*sp && *sp != ' ') sp++;
            char codebuf[8];
            size_t clen = (size_t)(sp - code);
            if (clen >= sizeof(codebuf)) clen = sizeof(codebuf) - 1;
            memcpy(codebuf, code, clen);
            codebuf[clen] = '\0';
            rh->status = atoi(codebuf);
            while (*sp == ' ') sp++;
            u_strcpyz(rh->reason, sizeof(rh->reason), sp);
        } else {
            const char *colon = strchr(line, ':');
            if (colon) {
                char name[64];
                size_t nlen = (size_t)(colon - line);
                if (nlen >= sizeof(name)) nlen = sizeof(name) - 1;
                memcpy(name, line, nlen);
                name[nlen] = '\0';
                url_header_add(&rh->headers, name, colon + 1);
            }
        }
    }
    return 0;
}

// Parse a hex chunk-size line, ignoring ";extensions" (UINT64_MAX on error)
uint64_t url_http_chunk_size(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    uint64_t v = 0;
    int any = 0;
    while (*p) {
        char c = *p;
        if (c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return UINT64_MAX;
        if (v > (UINT64_MAX - (uint64_t)d) / 16) return UINT64_MAX;
        v = v * 16 + (uint64_t)d;
        any = 1;
        p++;
    }
    return any ? v : UINT64_MAX;
}

// Decode chunked transfer encoding to raw data
int url_http_chunked_decode(const char *in, size_t in_len, char *out, size_t out_max, size_t *out_len) {
    size_t pos = 0, w = 0;
    while (pos < in_len) {
        const char *nl = memchr(in + pos, '\n', in_len - pos);
        if (!nl) return -1;
        size_t linelen = (size_t)(nl - (in + pos));
        char line[128];
        size_t cplen = linelen < sizeof(line) - 1 ? linelen : sizeof(line) - 1;
        memcpy(line, in + pos, cplen);
        line[cplen] = '\0';
        uint64_t sz = url_http_chunk_size(line);
        if (sz == UINT64_MAX) return -1;
        pos += linelen + 1;

        if (sz == 0) {
            while (pos < in_len) {
                const char *nl2 = memchr(in + pos, '\n', in_len - pos);
                if (!nl2) return -1;
                size_t tl = (size_t)(nl2 - (in + pos));
                if (tl == 1 && in[pos] == '\r') { pos += 2; break; }
                if (tl == 0) { pos += 1; break; }
                pos += tl + 1;
            }
            break;
        }
        if (sz > out_max - w) return -1;
        if (pos + (size_t)sz + 2 > in_len) return -1;
        if (in[pos + (size_t)sz] != '\r' || in[pos + (size_t)sz + 1] != '\n') return -1;
        memcpy(out + w, in + pos, (size_t)sz);
        w += (size_t)sz;
        pos += (size_t)sz + 2;
    }
    *out_len = w;
    return 0;
}

// Pick the method to use when following a redirect
int url_redirect_method(const char *method, int status, char *out, size_t outlen) {
    if (status == 301 || status == 302 || status == 303) {
        if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
            u_strcpyz(out, outlen, method);
        } else {
            u_strcpyz(out, outlen, "GET");
        }
        return 0;
    }
    u_strcpyz(out, outlen, method);
    return 0;
}

// Guess MIME type based on file extension
static void guess_mime(const char *name, char *out, size_t outlen) {
    const char *dot = strrchr(name, '.');
    const char *ext = dot ? dot + 1 : "";
    const char *mime = "application/octet-stream";
    if (_stricmp(ext, "txt") == 0 || _stricmp(ext, "text") == 0) mime = "text/plain";
    else if (_stricmp(ext, "html") == 0 || _stricmp(ext, "htm") == 0) mime = "text/html";
    else if (_stricmp(ext, "css") == 0) mime = "text/css";
    else if (_stricmp(ext, "js") == 0) mime = "application/javascript";
    else if (_stricmp(ext, "json") == 0) mime = "application/json";
    else if (_stricmp(ext, "xml") == 0) mime = "application/xml";
    else if (_stricmp(ext, "png") == 0) mime = "image/png";
    else if (_stricmp(ext, "jpg") == 0 || _stricmp(ext, "jpeg") == 0) mime = "image/jpeg";
    else if (_stricmp(ext, "gif") == 0) mime = "image/gif";
    else if (_stricmp(ext, "webp") == 0) mime = "image/webp";
    else if (_stricmp(ext, "svg") == 0) mime = "image/svg+xml";
    else if (_stricmp(ext, "pdf") == 0) mime = "application/pdf";
    else if (_stricmp(ext, "zip") == 0) mime = "application/zip";
    u_strcpyz(out, outlen, mime);
}

// Build multipart form data body with boundary
int url_multipart_build(const char *forms[], int n, char **out, size_t *outlen,
                        char *boundary, size_t bsz) {
    static const char hexd[] = "0123456789abcdef"; // hex digits for the boundary
    if (bsz < 48) return -1;
    strcpy(boundary, "------------------------");
    unsigned seed = (unsigned)(net_tick() ^ (uintptr_t)forms);
    size_t bpos = 24;
    for (int k = 0; k < 12 && bpos + 1 < bsz; k++) {
        seed = seed * 1664525u + 1013904223u;
        boundary[bpos++] = hexd[(seed >> 16) & 0xF];
    }
    boundary[bpos] = '\0';

    StrBuf b;
    sb_init(&b);
    for (int i = 0; i < n; i++) {
        const char *f = forms[i];
        const char *eq = strchr(f, '=');
        if (!eq) { sb_free(&b); return -1; }
        char fname[256];
        size_t fl = (size_t)(eq - f);
        if (fl >= sizeof(fname)) fl = sizeof(fname) - 1;
        memcpy(fname, f, fl);
        fname[fl] = '\0';

        const char *val = eq + 1;
        const char *semi = strchr(val, ';');
        char type[128] = { 0 };
        if (semi) {
            const char *t = strstr(semi, "type=");
            if (t) {
                t += 5;
                size_t tl = strcspn(t, " \t");
                if (tl >= sizeof(type)) tl = sizeof(type) - 1;
                memcpy(type, t, tl);
                type[tl] = '\0';
            }
        }
        size_t vlen = semi ? (size_t)(semi - val) : strlen(val);
        char vname[1024];
        if (vlen >= sizeof(vname)) vlen = sizeof(vname) - 1;
        memcpy(vname, val, vlen);
        vname[vlen] = '\0';

        sb_appends(&b, "--");
        sb_appends(&b, boundary);
        sb_appends(&b, "\r\n");
        if (vname[0] == '@') {
            const char *path = vname + 1;
            const char *bn = path;
            const char *bslash = strrchr(path, '/');
            const char *bback = strrchr(path, '\\');
            if (bslash && (!bback || bslash > bback)) bn = bslash + 1;
            else if (bback) bn = bback + 1;
            if (!type[0]) guess_mime(bn, type, sizeof(type));
            sb_appends(&b, "Content-Disposition: form-data; name=\"");
            sb_appends(&b, fname);
            sb_appends(&b, "\"; filename=\"");
            sb_appends(&b, bn);
            sb_appends(&b, "\"\r\n");
            sb_appends(&b, "Content-Type: ");
            sb_appends(&b, type);
            sb_appends(&b, "\r\n\r\n");
            if (sb_read_file(&b, path) != 0) { sb_free(&b); return -1; }
            sb_appends(&b, "\r\n");
        } else {
            sb_appends(&b, "Content-Disposition: form-data; name=\"");
            sb_appends(&b, fname);
            sb_appends(&b, "\"\r\n\r\n");
            sb_appends(&b, vname);
            sb_appends(&b, "\r\n");
        }
    }
    sb_appends(&b, "--");
    sb_appends(&b, boundary);
    sb_appends(&b, "--\r\n");
    *out = b.s;
    *outlen = b.len;
    return 0;
}

// ============================ Cookie jar ============================
// One process-wide cookie list shared by every UrlCtx. Entries are matched
// per RFC 6265 basics: domain suffix (or exact host for host-only cookies),
// path prefix, Secure only over TLS, expiry by epoch seconds (0 = session).
// File format (tab separated, one cookie per line):
//   domain<TAB>path<TAB>name<TAB>value<TAB>secure<TAB>expires

// One stored cookie
typedef struct {
    char domain[256];
    char path[512];
    char name[128];
    char value[1024];
    int secure;
    int host_only;
    long long expires; // epoch seconds; 0 = session
} cookie_t;

// Shared cookie list and its capacity
static cookie_t *g_cookies = NULL;
static int g_count = 0, g_cap = 0;
// 1 once the shared list has been loaded from a file (url_cookie_load)
static int g_cookie_loaded = 0;

#ifdef _WIN32
static CRITICAL_SECTION g_cookie_lock;
static int g_cookie_lock_init = 0;
static void cookie_lock(void) {
    if (!g_cookie_lock_init) { InitializeCriticalSection(&g_cookie_lock); g_cookie_lock_init = 1; }
    EnterCriticalSection(&g_cookie_lock);
}
static void cookie_unlock(void) { LeaveCriticalSection(&g_cookie_lock); }
#else
static pthread_mutex_t g_cookie_lock = PTHREAD_MUTEX_INITIALIZER;
static void cookie_lock(void)   { pthread_mutex_lock(&g_cookie_lock); }
static void cookie_unlock(void) { pthread_mutex_unlock(&g_cookie_lock); }
#endif

// Lowercase a string in place
static void cookie_lower(char *s) {
    for (; *s; s++)
        *s = (char)tolower((unsigned char)*s);
}

// Split "scheme://host[:port]/path" into lowercased host and path
static void cookie_split_url(const char *url, char *host, size_t hsz, char *path, size_t psz, int *is_ssl) {
    const char *p = strstr(url, "://");
    const char *h;
    host[0] = 0;
    path[0] = '/';
    path[1] = 0;
    *is_ssl = 0;
    if (!p) return;
    *is_ssl = (p - url == 5 && _strnicmp(url, "https", 5) == 0);
    h = p + 3;
    {
        size_t i = 0;
        while (*h && *h != '/' && *h != '?' && *h != '#' && i + 1 < hsz) {
            if (*h == ':') { // port: skip to the path
                while (*h && *h != '/') h++;
                break;
            }
            host[i++] = *h++;
        }
        host[i] = 0;
        cookie_lower(host);
    }
    if (*h == '/') {
        size_t i = 0;
        while (*h && *h != '?' && *h != '#' && i + 1 < psz)
            path[i++] = *h++;
        path[i] = 0;
    }
}

// Default cookie path = directory of the request path
static void cookie_default_path(const char *req_path, char *out, size_t osz) {
    const char *slash = strrchr(req_path, '/');
    if (!slash || slash == req_path) {
        snprintf(out, osz, "/");
        return;
    }
    {
        size_t l = (size_t)(slash - req_path) + 1;
        if (l >= osz) l = osz - 1;
        memcpy(out, req_path, l);
        out[l] = 0;
    }
}

// Map "Jan".."Dec" (case-insensitive) to 0..11, or -1
static int cookie_month_num(const char *m) {
    static const char *mo[] = {"Jan","Feb","Mar","Apr","May","Jun",
                               "Jul","Aug","Sep","Oct","Nov","Dec"};
    int i;
    for (i = 0; i < 12; i++)
        if (_strnicmp(m, mo[i], 3) == 0) return i;
    return -1;
}

// Parse "Wdy, DD Mon YYYY HH:MM:SS GMT" into epoch seconds (approx)
static long long cookie_parse_date(const char *s) {
    int day = 0, mon = -1, yr = 0, hh = 0, mm = 0, ss = 0;
    const char *p = s;
    while (*p && !isdigit((unsigned char)*p)) p++;
    if (sscanf(p, "%d", &day) != 1) return -1;
    while (*p && !isalpha((unsigned char)*p)) p++;
    if ((mon = cookie_month_num(p)) < 0) return -1;
    while (*p && !isdigit((unsigned char)*p)) p++;
    if (sscanf(p, "%d", &yr) != 1) return -1;
    while (*p && *p != ':') p++; // skip to time
    if (*p == ':') { p++; sscanf(p, "%d:%d", &hh, &mm); }
    while (*p && *p != ':') p++;
    if (*p == ':') { p++; sscanf(p, "%d", &ss); }
    {
        struct tm tm;
        memset(&tm, 0, sizeof(tm));
        tm.tm_mday = day; tm.tm_mon = mon; tm.tm_year = yr - 1900;
        tm.tm_hour = hh; tm.tm_min = mm; tm.tm_sec = ss;
        return (long long)mktime(&tm);
    }
}

// Insert or update a cookie; an expired one removes the existing match
static void cookie_store(cookie_t c) {
    int i;
    long long now = (long long)time(NULL);
    if (c.expires != 0 && c.expires <= now) {
        for (i = 0; i < g_count; i++) {
            if (strcmp(g_cookies[i].domain, c.domain) == 0 &&
                strcmp(g_cookies[i].path, c.path) == 0 &&
                strcmp(g_cookies[i].name, c.name) == 0) {
                g_cookies[i] = g_cookies[g_count - 1];
                g_count--;
                return;
            }
        }
        return;
    }
    for (i = 0; i < g_count; i++) {
        if (strcmp(g_cookies[i].domain, c.domain) == 0 &&
            strcmp(g_cookies[i].path, c.path) == 0 &&
            strcmp(g_cookies[i].name, c.name) == 0) {
            g_cookies[i] = c;
            return;
        }
    }
    if (g_count == g_cap) {
        int nc = g_cap ? g_cap * 2 : 64;
        cookie_t *nv = (cookie_t *)realloc(g_cookies, (size_t)nc * sizeof(cookie_t));
        if (!nv) return;
        g_cookies = nv;
        g_cap = nc;
    }
    g_cookies[g_count++] = c;
}

void url_cookie_set_from_url(const char *url, const char *set_cookie) {
    char host[256], path[512];
    int is_ssl;
    cookie_t c;
    const char *p, *end;

    if (!url || !set_cookie || !set_cookie[0]) return;
    memset(&c, 0, sizeof(c));
    cookie_split_url(url, host, sizeof(host), path, sizeof(path), &is_ssl);
    if (!host[0]) return;

    // name=value
    p = set_cookie;
    while (*p == ' ') p++;
    end = strchr(p, '=');
    if (!end) return;
    {
        size_t l = (size_t)(end - p);
        if (l >= sizeof(c.name)) l = sizeof(c.name) - 1;
        memcpy(c.name, p, l);
        c.name[l] = 0;
    }
    p = end + 1;
    end = strchr(p, ';');
    {
        size_t l = end ? (size_t)(end - p) : strlen(p);
        if (l >= sizeof(c.value)) l = sizeof(c.value) - 1;
        memcpy(c.value, p, l);
        c.value[l] = 0;
    }

    snprintf(c.domain, sizeof(c.domain), "%s", host);
    c.host_only = 1;
    cookie_default_path(path, c.path, sizeof(c.path));
    c.expires = 0;
    c.secure = is_ssl ? 0 : 0;

    // attributes
    while (end) {
        const char *a;
        p = end + 1;
        while (*p == ' ') p++;
        end = strchr(p, ';');
        {
            size_t l = end ? (size_t)(end - p) : strlen(p);
            char attr[512];
            if (l >= sizeof(attr)) l = sizeof(attr) - 1;
            memcpy(attr, p, l);
            attr[l] = 0;
            a = attr;
            while (*a == ' ') a++;
            if (_strnicmp(a, "domain=", 7) == 0) {
                char d[256];
                snprintf(d, sizeof(d), "%s", a + 7);
                while (*d == ' ') memmove(d, d + 1, strlen(d));
                { size_t dl = strlen(d); while (dl && (d[dl-1]==' ')) d[--dl]=0; }
                if (d[0] == '.') memmove(d, d + 1, strlen(d));
                cookie_lower(d);
                if (d[0]) {
                    snprintf(c.domain, sizeof(c.domain), "%s", d);
                    c.host_only = 0;
                }
            } else if (_strnicmp(a, "path=", 5) == 0) {
                char pp[512];
                snprintf(pp, sizeof(pp), "%s", a + 5);
                { size_t pl = strlen(pp); while (pl && pp[pl-1]==' ') pp[--pl]=0; }
                if (pp[0] == '/')
                    snprintf(c.path, sizeof(c.path), "%s", pp);
            } else if (_strnicmp(a, "secure", 6) == 0) {
                c.secure = 1;
            } else if (_strnicmp(a, "max-age=", 8) == 0) {
                long long ma = atoll(a + 8);
                c.expires = (long long)time(NULL) + ma;
            } else if (_strnicmp(a, "expires=", 8) == 0) {
                long long e = cookie_parse_date(a + 8);
                if (e > 0 && c.expires == 0) c.expires = e;
            }
        }
        if (!end) break;
    }

    cookie_lock();
    cookie_store(c);
    cookie_unlock();
}

// 1 if the cookie domain matches the request host
static int cookie_domain_match(const cookie_t *c, const char *host) {
    size_t dl = strlen(c->domain), hl = strlen(host);
    if (hl == dl && _stricmp(host, c->domain) == 0) return 1;
    if (!c->host_only && hl > dl && host[hl - dl - 1] == '.' &&
        _stricmp(host + hl - dl, c->domain) == 0)
        return 1;
    return 0;
}

char *url_cookie_header_for(const char *url) {
    char host[256], path[512], out[8192];
    int is_ssl;
    size_t o = 0;
    int i;
    long long now = (long long)time(NULL);

    if (!url) return NULL;
    cookie_split_url(url, host, sizeof(host), path, sizeof(path), &is_ssl);
    if (!host[0]) return NULL;
    out[0] = 0;

    cookie_lock();
    for (i = 0; i < g_count; i++) {
        cookie_t *c = &g_cookies[i];
        size_t pl;
        if (c->expires != 0 && c->expires <= now) continue;
        if (c->secure && !is_ssl) continue;
        if (!cookie_domain_match(c, host)) continue;
        pl = strlen(c->path);
        if (pl && strncmp(path, c->path, pl) != 0) continue;
        {
            char part[1200];
            snprintf(part, sizeof(part), "%s%s=%s", o ? "; " : "", c->name, c->value);
            if (o + strlen(part) + 1 >= sizeof(out)) break;
            memcpy(out + o, part, strlen(part) + 1);
            o += strlen(part);
        }
    }
    cookie_unlock();
    if (o == 0) return NULL;
    return x_strdup(out);
}

void url_cookie_load(const char *file) {
    FILE *f;
    char line[2400];
    if (!file) return;
    cookie_lock();
    f = fopen(file, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            cookie_t c;
            char *t1, *t2, *t3, *t4, *t5;
            size_t l = strlen(line);
            while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
            if (!line[0] || line[0] == '#') continue;
            memset(&c, 0, sizeof(c));
            t1 = strchr(line, '\t');
            if (!t1) continue;
            *t1++ = 0;
            t2 = strchr(t1, '\t'); if (!t2) continue; *t2++ = 0;
            t3 = strchr(t2, '\t'); if (!t3) continue; *t3++ = 0;
            t4 = strchr(t3, '\t'); if (!t4) continue; *t4++ = 0;
            t5 = strchr(t4, '\t'); if (!t5) continue; *t5++ = 0;
            snprintf(c.domain, sizeof(c.domain), "%s", line);
            snprintf(c.path, sizeof(c.path), "%s", t1);
            snprintf(c.name, sizeof(c.name), "%s", t2);
            snprintf(c.value, sizeof(c.value), "%s", t3);
            c.secure = atoi(t4);
            c.expires = atoll(t5);
            c.host_only = 1;
            if (g_count == g_cap) {
                int nc = g_cap ? g_cap * 2 : 64;
                cookie_t *nv = (cookie_t *)realloc(g_cookies, (size_t)nc * sizeof(cookie_t));
                if (!nv) break;
                g_cookies = nv;
                g_cap = nc;
            }
            g_cookies[g_count++] = c;
        }
        fclose(f);
    }
    cookie_unlock();
}

void url_cookie_save(const char *file) {
    FILE *f;
    int i;
    long long now = (long long)time(NULL);
    if (!file) return;
    cookie_lock();
    f = fopen(file, "w");
    if (f) {
        for (i = 0; i < g_count; i++) {
            cookie_t *c = &g_cookies[i];
            if (c->expires != 0 && c->expires <= now) continue;
            fprintf(f, "%s\t%s\t%s\t%s\t%d\t%lld\n", c->domain, c->path,
                    c->name, c->value, c->secure, c->expires);
        }
        fclose(f);
    }
    cookie_unlock();
}

// Build HTTP request string with headers
char *url_build_request(const UrlCtx *ctx, const UrlInfo *u, const char *method,
                        const char *content_type, const char *range,
                        const char *body, size_t body_len, size_t *out_len) {
    StrBuf sb;
    sb_init(&sb);
    sb_appends(&sb, method);
    sb_appendc(&sb, ' ');
    sb_appends(&sb, u->path);
    sb_appends(&sb, " HTTP/1.1\r\n");

    HeaderList L = { 0 };
    char hostbuf[URL_MAX_HOST + 32];
    int defport = u->is_ssl ? 443 : 80;
    if (u->port == defport)
        u_strcpyz(hostbuf, sizeof(hostbuf), u->host);
    else {
        u_strcpyz(hostbuf, sizeof(hostbuf), u->host);
        u_strcat(hostbuf, sizeof(hostbuf), ":");
        u_strcat_int(hostbuf, sizeof(hostbuf), u->port);
    }
    url_header_add(&L, "Host", hostbuf);
    url_header_add(&L, "User-Agent", ctx->user_agent[0] ? ctx->user_agent : "curl/8.6.0");
    url_header_add(&L, "Accept", "*/*");
    if (content_type) {
        url_header_add(&L, "Content-Type", content_type);
        char cl[32] = { 0 };
        u_strcat_size(cl, sizeof(cl), body_len);
        url_header_add(&L, "Content-Length", cl);
    }
    if (range) url_header_add(&L, "Range", range);
    url_header_add(&L, "Connection", "close");

    /* attach stored cookies for this URL (shared jar, if enabled) */
    if (ctx->use_cook) {
        char curl[URL_MAX_PATH * 2 + 128];
        snprintf(curl, sizeof(curl), "%s://%s%s", u->is_ssl ? "https" : "http",
                 u->host, u->path);
        {
            char *ck = url_cookie_header_for(curl);
            if (ck) {
                url_header_add(&L, "Cookie", ck);
                free(ck);
            }
        }
    }

    for (int i = 0; i < ctx->headers.n; i++)
        url_header_add(&L, ctx->headers.h[i].name, ctx->headers.h[i].value);

    for (int i = 0; i < L.n; i++) {
        char fname[64] = { 0 };
        const char *h = L.h[i].name;
        if (strcmp(h, "host") == 0) strcpy(fname, "Host");
        else if (strcmp(h, "user-agent") == 0) strcpy(fname, "User-Agent");
        else if (strcmp(h, "accept") == 0) strcpy(fname, "Accept");
        else if (strcmp(h, "content-type") == 0) strcpy(fname, "Content-Type");
        else if (strcmp(h, "content-length") == 0) strcpy(fname, "Content-Length");
        else if (strcmp(h, "range") == 0) strcpy(fname, "Range");
        else if (strcmp(h, "connection") == 0) strcpy(fname, "Connection");
        else strcpy(fname, h);
        sb_appends(&sb, fname);
        sb_appends(&sb, ": ");
        sb_appends(&sb, L.h[i].value);
        sb_appends(&sb, "\r\n");
    }
    sb_appends(&sb, "\r\n");
    if (body && body_len > 0) sb_append(&sb, body, body_len);

    *out_len = sb.len;
    return sb.s;
}

// Resolve hostname and connect with optional timeout
static SOCKET connect_to_host(const char *host, int port, int timeout_ms,
                              char *ip, size_t ip_sz) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char ps[16] = { 0 };
    u_strcat_int(ps, sizeof(ps), port);
    if (getaddrinfo(host, ps, &hints, &res) != 0) return INVALID_SOCKET;

    SOCKET sock = INVALID_SOCKET;
    for (ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == INVALID_SOCKET) continue;

        if (timeout_ms > 0) {
            set_nonblocking(sock, 1);
            int rc = connect(sock, ai->ai_addr, (int)ai->ai_addrlen);
            if (rc != 0 && net_err() != NET_INPROGRESS) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            fd_set w;
            FD_ZERO(&w);
            FD_SET(sock, &w);
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sel = select((int)sock + 1, NULL, &w, NULL, &tv);
            if (sel <= 0) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &elen);
            if (err != 0) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
            set_nonblocking(sock, 0);
        } else {
            if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }
        }

        if (ip && ip_sz) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
            inet_ntop(AF_INET, &sin->sin_addr, ip, (int)ip_sz);
        }
        break;
    }
    freeaddrinfo(res);

    if (sock != INVALID_SOCKET) {
        /* SO_RCVTIMEO should be shorter than the SSL io_timeout because
         * ssl_sock_read may call recv() twice (initial + retry).
         * Using half the timeout ensures total wait <= io_timeout. */
        int tm = timeout_ms > 0 ? timeout_ms / 2 : 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tm, sizeof(tm));
    }
    return sock;
}

// Establish TLS connection on top of socket
static SSL *tls_connect_socket(SOCKET sock, const char *host, int insecure, int verbose, int io_timeout, UrlLogFn log) {
    SSL_CTX *ctx = SSL_CTX_new();
    if (!ctx) return NULL;
    ssl_set_io_timeout(ctx, io_timeout);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return NULL; }
    SSL_set_fd(ssl, (int)sock);
    if (insecure) SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    else SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    tls_set_server_name((TLSContext *)ssl, host, (int)strlen(host));

    int ret = SSL_connect(ssl);
    if (ret != 0) {
        int err = SSL_get_error(ssl, ret);
#if URL_LOGGING
        if (verbose && log) log("* TLS handshake failed (error=%d)\n", err);
#endif
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_free(ctx);
    return ssl;
}

// Transport structure for unified socket/SSL I/O
typedef struct {
    SOCKET sock;
    SSL *ssl;
    int is_ssl;
    char pending[65536];
    int pending_len;
    int eof;
} Transport;

// Fill pending buffer from socket or SSL connection
static int tp_fill(Transport *t) {
    if (t->pending_len > 0) return 1;
    char buf[16384];
    int n;
    if (t->is_ssl) {
        int retries = 0;
        for (;;) {
            n = SSL_read(t->ssl, buf, (int)sizeof(buf));
            if (n > 0) break;
            if (n == 0) {
                /* SSL_read returned 0 = clean close (close_notify).
                 * Accept whatever we have or signal EOF. */
                t->eof = 1;
                return t->pending_len > 0 ? 1 : 0;
            }
            /* SSL_read returned -1. Check if it's a transient timeout
             * (rw_error == 0) or a real socket error (rw_error == 1).
             * ssl_sock_read sets rw_error=1 only for real errors like
             * ECONNRESET; for timeouts/EAGAIN it stays 0. */
            SSLInternal *si = ssl_get_internal(t->ssl);
            if (si && si->rw_error) {
                return -1;
            }
            retries++;
            if (retries > 5) {
                t->eof = 1;
                return 0;
            }
            net_sleep(2);
        }
    } else {
        int retries = 0;
        for (;;) {
            n = (int)recv(t->sock, buf, (int)sizeof(buf), 0);
            if (n > 0) break;
            if (n == 0) {
                t->eof = 1;
                return t->pending_len > 0 ? 1 : 0;
            }
            int err = net_err();
            if (err == NET_CONNRESET || err == NET_TIMEDOUT) {
                t->eof = 1;
                return t->pending_len > 0 ? 1 : 0;
            }
            retries++;
            if (retries > 5) {
                t->eof = 1;
                return 0;
            }
            net_sleep(2);
        }
    }
    memcpy(t->pending, buf, (size_t)n);
    t->pending_len = n;
    return 1;
}

// Read bytes from transport pending buffer
static int tp_read(Transport *t, char *out, int len) {
    if (!tp_fill(t)) return 0;
    int n = len < t->pending_len ? len : t->pending_len;
    memcpy(out, t->pending, (size_t)n);
    t->pending_len -= n;
    memmove(t->pending, t->pending + n, (size_t)t->pending_len);
    return n;
}

// Read one line from transport without CR/LF
static int tp_read_line(Transport *t, char *out, int sz) {
    int got = 0;
    while (got < sz - 1) {
        if (!tp_fill(t)) break;
        char *nl = memchr(t->pending, '\n', (size_t)t->pending_len);
        if (nl) {
            int take = (int)(nl - t->pending) + 1;
            if (got + take > sz - 1) take = sz - 1 - got;
            memcpy(out + got, t->pending, (size_t)take);
            got += take;
            t->pending_len -= take;
            memmove(t->pending, t->pending + take, (size_t)t->pending_len);
            break;
        } else {
            int take = t->pending_len;
            if (got + take > sz - 1) take = sz - 1 - got;
            memcpy(out + got, t->pending, (size_t)take);
            got += take;
            t->pending_len -= take;
            memmove(t->pending, t->pending + take, (size_t)t->pending_len);
        }
    }
    if (got == 0) return 0;
    out[got] = '\0';
    while (got > 0 && (out[got - 1] == '\n' || out[got - 1] == '\r')) out[--got] = '\0';
    return 1;
}

// Close transport (SSL and socket)
static void close_transport(Transport *t) {
    if (t->ssl) {
        SSL_shutdown(t->ssl);
        SSL_free(t->ssl);
        t->ssl = NULL;
    }
    if (t->sock != INVALID_SOCKET) {
        shutdown(t->sock, SD_BOTH);
        closesocket(t->sock);
        t->sock = INVALID_SOCKET;
    }
}

// Read HTTP status line and headers from transport
static int read_status_and_headers(Transport *t, ResponseHead *rh) {
    StrBuf raw;
    sb_init(&raw);
    for (;;) {
        char line[8192];
        if (!tp_read_line(t, line, sizeof(line))) break;
        sb_appends(&raw, line);
        sb_appends(&raw, "\r\n");
        if (line[0] == '\0') break;
        if (raw.len > (1u << 20)) break;
    }
    int rc = url_http_parse_status_and_headers(raw.s, raw.len, rh);
    sb_free(&raw);
    return rc;
}

// Log request lines for verbose output
static void verbose_request(UrlLogFn log, const char *req) {
    if (!log) return;
#if URL_LOGGING
    const char *p = req;
    while (*p) {
        const char *nl = strstr(p, "\r\n");
        if (!nl) break;
        size_t llen = (size_t)(nl - p);
        if (llen == 0) {
            log(">\n");
            break;
        }
        log("> %.*s\n", (int)llen, p);
        p = nl + 2;
    }
#endif
}

// Log response status and headers for verbose output
static void verbose_response(UrlLogFn log, const ResponseHead *rh) {
    if (!log) return;
#if URL_LOGGING
    log("< HTTP/%s %d %s\n", rh->version, rh->status, rh->reason);
    for (int i = 0; i < rh->headers.n; i++)
        log("< %s: %s\n", rh->headers.h[i].name, rh->headers.h[i].value);
    log("<\n");
#endif
}

// Read fixed-length body from transport into a string buffer
static int read_body_fixed(Transport *t, uint64_t len, StrBuf *b) {
    char buf[16384];
    uint64_t got = 0;
    while (got < len) {
        size_t want = sizeof(buf);
        if (len - got < want) want = (size_t)(len - got);
        int n = tp_read(t, buf, (int)want);
        if (n <= 0) break;
        sb_append(b, buf, (size_t)n);
        got += (uint64_t)n;
    }
    return 0;
}

// Read chunked-encoded body from transport into a string buffer
static int read_body_chunked(Transport *t, StrBuf *b) {
    char line[256];
    for (;;) {
        if (!tp_read_line(t, line, sizeof(line))) return 0;
        uint64_t sz = url_http_chunk_size(line);
        if (sz == UINT64_MAX) return -1;
        if (sz == 0) {
            while (tp_read_line(t, line, sizeof(line))) {
                if (line[0] == '\0') break;
            }
            return 0;
        }
        uint64_t rem = sz;
        char buf[16384];
        while (rem > 0) {
            size_t want = sizeof(buf);
            if (rem < want) want = (size_t)rem;
            int n = tp_read(t, buf, (int)want);
            if (n <= 0) {
                if (t->eof) return 0;
                return -1;
            }
            sb_append(b, buf, (size_t)n);
            rem -= (uint64_t)n;
        }
        if (!tp_read_line(t, line, sizeof(line))) return 0;
    }
}

// Read body until EOF from transport into a string buffer
static int read_body_to_eof(Transport *t, StrBuf *b) {
    char buf[16384];
    for (;;) {
        int n = tp_read(t, buf, (int)sizeof(buf));
        if (n <= 0) break;
        sb_append(b, buf, (size_t)n);
    }
    return 0;
}

// Read response body based on transfer encoding
static int read_body(Transport *t, int is_head, const ResponseHead *rh, StrBuf *b) {
    if (is_head) return 0;
    const char *te = url_header_get(&rh->headers, "transfer-encoding");
    const char *cl = url_header_get(&rh->headers, "content-length");
    if (te && strstr(te, "chunked")) return read_body_chunked(t, b);
    if (cl) return read_body_fixed(t, strtoull(cl, NULL, 10), b);
    return read_body_to_eof(t, b);
}

// Serialize a parsed response head back to its HTTP/1.1 wire form
static void append_response_head(StrBuf *b, const ResponseHead *rh) {
    sb_appends(b, "HTTP/");
    sb_appends(b, rh->version);
    sb_appendc(b, ' ');
    sb_append_int(b, rh->status);
    sb_appendc(b, ' ');
    sb_appends(b, rh->reason);
    sb_appends(b, "\r\n");
    for (int i = 0; i < rh->headers.n; i++) {
        sb_appends(b, rh->headers.h[i].name);
        sb_appends(b, ": ");
        sb_appends(b, rh->headers.h[i].value);
        sb_appends(b, "\r\n");
    }
    sb_appends(b, "\r\n");
}

// Create a request context with defaults
UrlCtx *url_init(void) {
    UrlCtx *ctx = (UrlCtx *)calloc(1, sizeof(UrlCtx));
    if (!ctx) return NULL;
    ctx->max_redirs = URL_MAX_REDIRS;
    ctx->connect_timeout_ms = -1;
    return ctx;
}

// Free a context (including ctx->data if set)
void url_free(UrlCtx *ctx) {
    if (!ctx) return;
    free(ctx->data);
    ctx->data = NULL;
    free(ctx);
}

// Add or replace a request header (case-insensitive)
void url_set_header(UrlCtx *ctx, const char *name, const char *value) {
    if (!ctx) return;
    url_header_add(&ctx->headers, name, value);
}

// Set the User-Agent header ("" restores the default)
void url_set_user_agent(UrlCtx *ctx, const char *ua) {
    if (!ctx) return;
    if (ua) u_strcpyz(ctx->user_agent, sizeof(ctx->user_agent), ua);
    else ctx->user_agent[0] = '\0';
}

// Copy `len` bytes as the request body (replaces any previous body)
void url_set_data(UrlCtx *ctx, const char *data, size_t len) {
    if (!ctx) return;
    free(ctx->data);
    ctx->data = NULL;
    ctx->data_len = 0;
    if (!data || len == 0) return;
    char *buf = (char *)malloc(len + 1);
    if (!buf) return;
    memcpy(buf, data, len);
    buf[len] = '\0';
    ctx->data = buf;
    ctx->data_len = len;
}

// Set the Content-Type header ("" clears it)
void url_set_content_type(UrlCtx *ctx, const char *ct) {
    if (!ctx) return;
    if (ct) u_strcpyz(ctx->content_type, sizeof(ctx->content_type), ct);
    else ctx->content_type[0] = '\0';
}

// Set the Range request header ("" clears it)
void url_set_range(UrlCtx *ctx, const char *range) {
    if (!ctx) return;
    if (range) u_strcpyz(ctx->range, sizeof(ctx->range), range);
    else ctx->range[0] = '\0';
}

// HTTP status code of the last url_run() response (0 if none)
int url_status(const UrlCtx *ctx) {
    return ctx ? ctx->last_status : 0;
}

// Header value of the last url_run() response (case-insensitive), or NULL
const char *url_response_header(const UrlCtx *ctx, const char *name) {
    if (!ctx) return NULL;
    return url_header_get(&ctx->last_head.headers, name);
}

/*
 * Perform the HTTP(S) request and return the response body as a malloc'ed
 * string. Returns NULL on failure and records the error in ctx->last_error.
 * Console output (verbose progress and error messages) is routed through the
 * optional log callback (NULL = no logging).
 */
char *url_run(UrlCtx *ctx, const char *url, const char *method, UrlLogFn log) {
    if (!ctx || !url || !method) return NULL;

    ctx->last_status = 0;
    ctx->last_error = 0;
    memset(&ctx->last_head, 0, sizeof(ctx->last_head));
    ctx->result_len = 0;

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        ctx->last_error = URL_ERR_INIT;
        return NULL;
    }
#endif
    long io_timeout = ctx->connect_timeout_set ? ctx->connect_timeout_ms : 10000;

    char current_url[URL_MAX_PATH * 2 + 128];
    u_strcpyz(current_url, sizeof(current_url), url);

    /* load the shared cookie jar from the file once, if this context uses one */
    if (ctx->use_cook && !g_cookie_loaded && ctx->cook_file) {
        url_cookie_load(ctx->cook_file);
        g_cookie_loaded = 1;
    }

    int redirs = 0;
    int failed = 0;
    int use_body = (ctx->data != NULL && ctx->data_len > 0);
    UrlInfo u;
    StrBuf out;
    sb_init(&out);

    for (;;) {
        if (url_parse(current_url, &u) != 0) {
#if URL_LOGGING
            if (!ctx->silent && log) log("curl: (1) URL rejected: %s\n", current_url);
#endif
            ctx->last_error = URL_ERR_INVALID_URL;
            failed = 1;
            break;
        }

        char ip[64] = { 0 };
#if URL_LOGGING
        if (ctx->verbose && log) log("*   Trying %s:%d...\n", u.host, u.port);
#endif
        SOCKET sock = connect_to_host(u.host, u.port, (int)io_timeout, ip, sizeof(ip));
        if (sock == INVALID_SOCKET) {
#if URL_LOGGING
            if (!ctx->silent && log)
                log("curl: (7) Failed to connect to %s port %d\n", u.host, u.port);
#endif
            ctx->last_error = URL_ERR_CONNECT;
            failed = 1;
            break;
        }
#if URL_LOGGING
        if (ctx->verbose && log)
            log("* Connected to %s (%s) port %d\n", u.host, ip[0] ? ip : u.host, u.port);
#endif

        Transport tr;
        memset(&tr, 0, sizeof(tr));
        tr.sock = sock;
        tr.is_ssl = u.is_ssl;

        if (u.is_ssl) {
#if URL_LOGGING
            if (ctx->verbose && log) log("* TLS: starting handshake\n");
#endif
            tr.ssl = tls_connect_socket(sock, u.host, ctx->insecure, ctx->verbose, (int)io_timeout, log);
            if (!tr.ssl) {
#if URL_LOGGING
                if (!ctx->silent && log) log("curl: (35) TLS handshake failed\n");
#endif
                ctx->last_error = URL_ERR_TLS;
                closesocket(sock);
                failed = 1;
                break;
            }
#if URL_LOGGING
            if (ctx->verbose && log) {
                log("* TLS version %s, cipher %s\n",
                        tls_negotiated_tls13((TLSContext *)tr.ssl) ? "1.3" : "1.2",
                        tls_cipher_name(tr.ssl));
            }
#endif
        }

        const char *send_body = use_body ? ctx->data : NULL;
        size_t send_len = use_body ? ctx->data_len : 0;
        const char *ct_use = use_body && ctx->content_type[0] ? ctx->content_type : NULL;
        const char *range = ctx->range[0] ? ctx->range : NULL;

        size_t req_len = 0;
        char *req = url_build_request(ctx, &u, method, ct_use, range, send_body, send_len, &req_len);
        if (!req) {
            ctx->last_error = URL_ERR_BUILD_REQUEST;
            close_transport(&tr);
            failed = 1;
            break;
        }
        if (ctx->verbose) verbose_request(log, req);

        int sent;
        if (u.is_ssl) sent = SSL_write(tr.ssl, req, (int)req_len);
        else sent = (int)send(sock, req, (unsigned int)req_len, 0);
        free(req);
        if (sent <= 0) {
#if URL_LOGGING
            if (!ctx->silent && log) log("curl: (55) failed to send request\n");
#endif
            ctx->last_error = URL_ERR_SEND;
            close_transport(&tr);
            failed = 1;
            break;
        }

        ResponseHead rh;
        if (read_status_and_headers(&tr, &rh) != 0) {
#if URL_LOGGING
            if (!ctx->silent && log) log("curl: (56) no HTTP response received\n");
#endif
            ctx->last_error = URL_ERR_RECV;
            close_transport(&tr);
            failed = 1;
            break;
        }
        if (ctx->verbose) verbose_response(log, &rh);
        ctx->last_status = rh.status;
        ctx->last_head = rh;

        /* store any Set-Cookie headers for later requests (shared jar) */
        if (ctx->use_cook) {
            int ck_changed = 0;
            for (int hi = 0; hi < rh.headers.n; hi++) {
                if (_stricmp(rh.headers.h[hi].name, "set-cookie") == 0) {
                    url_cookie_set_from_url(current_url, rh.headers.h[hi].value);
                    ck_changed = 1;
                }
            }
            if (ck_changed && ctx->cook_file)
                url_cookie_save(ctx->cook_file);
        }

        int is_head = (strcmp(method, "HEAD") == 0);
        StrBuf body_buf;
        sb_init(&body_buf);
        if (!is_head && rh.status != 204 && rh.status != 304) {
            if (read_body(&tr, is_head, &rh, &body_buf) != 0) {
#if URL_LOGGING
                if (!ctx->silent && log) log("curl: (18) failed to read response body\n");
#endif
            }
        }

        const char *loc = NULL;
        if (ctx->follow_redirects && rh.status >= 300 && rh.status < 400)
            loc = url_header_get(&rh.headers, "location");

        if (loc && *loc) {
            if (redirs >= ctx->max_redirs) {
#if URL_LOGGING
                if (!ctx->silent && log)
                    log("curl: (47) Maximum (%d) redirects followed\n", ctx->max_redirs);
#endif
                ctx->last_error = URL_ERR_MAX_REDIR;
                sb_free(&body_buf);
                close_transport(&tr);
                failed = 1;
                break;
            }
            char next[URL_MAX_PATH * 2 + 128];
            url_join(current_url, loc, next, sizeof(next));
#if URL_LOGGING
            if (ctx->verbose && log) log("* Redirecting to %s\n", next);
#endif

            char newm[16];
            url_redirect_method(method, rh.status, newm, sizeof(newm));
            if (strcmp(newm, method) != 0) {
                use_body = 0;   // RFC 7231: body dropped for the new GET
                method = newm;
            }

            close_transport(&tr);
            sb_free(&body_buf);
            u_strcpyz(current_url, sizeof(current_url), next);
            redirs++;
            continue;
        }

        // Final response: prepend the head if requested, then the body.
        if (ctx->include_headers)
            append_response_head(&out, &rh);
        if (body_buf.len > 0)
            sb_append(&out, body_buf.s, body_buf.len);
        sb_free(&body_buf);

        close_transport(&tr);
        break;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    if (failed) {
        sb_free(&out);
        return NULL;
    }
    if (!out.s) {
        // Empty body (HEAD, 204,...): return a valid empty string.
        out.s = (char *)malloc(1);
        if (out.s) out.s[0] = '\0';
        out.len = 0;
    }
    ctx->result_len = out.len;
    return out.s;
}
