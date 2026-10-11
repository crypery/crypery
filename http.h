/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * HTTP server module.
 *
 * HTTP/1.1 server over plain TCP or TLS with routing, static file serving,
 * gzip compression, WebSocket, SSE, query-string and multipart parsing, and
 * security checks. Create a server with http_init(), configure its fields,
 * register routes with http_route(), start it with http_run(), and release it
 * with http_free().
 */

#ifndef HTTP_H
#define HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Define HTTP_NO_GZIP to disable gzip compression at compile time:
 *   - zlib is not required (no zlib include, no -lz, no zlib/*.c sources)
 *   - static files are served uncompressed only
 * Example: gcc -DHTTP_NO_GZIP -o server.exe server.c http.c tls.c ssl.c json.c sett.c log.c -lws2_32
 */

#include "ssl.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Self-contained platform portability for the http module.
 *
 * The http module intentionally does NOT include compat.h; the socket, string,
 * and thread helpers it needs are provided here for both Windows (Winsock +
 * WinAPI) and POSIX (Berkeley sockets + pthreads). When compat.h is also
 * included in the same translation unit it detects the HTTP_PLAT_DEFINED
 * marker below and skips its overlapping definitions. */
#ifndef HTTP_PLAT_DEFINED
#define HTTP_PLAT_DEFINED

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <strings.h>

// --- socket aliases ---
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket    close
#define WSAGetLastError() (errno)
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAETIMEDOUT   EAGAIN
#define SD_BOTH        SHUT_RDWR
#define SD_SEND        SHUT_WR
#define SD_RECV        SHUT_RD

// --- string aliases ---
#define _stricmp   strcasecmp
#define _strnicmp  strncasecmp
#define strtok_s   strtok_r
#endif // _WIN32

// Monotonic tick counter in milliseconds.
static inline unsigned long compat_tick(void) {
#ifdef _WIN32
    return (unsigned long)GetTickCount();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long)(ts.tv_sec * 1000UL + ts.tv_nsec / 1000000UL);
#endif
}

/* Initialize the socket layer (WSAStartup on Windows, no-op on POSIX).
 * @return 0 on success. */
static inline int sock_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    return 0;
#endif
}

// Tear down the socket layer.
static inline void sock_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// --- mutual exclusion ---
#ifdef _WIN32
typedef CRITICAL_SECTION mtx_t;
static inline void mtx_init(mtx_t *m)   { InitializeCriticalSection(m); }
static inline void mtx_lock(mtx_t *m)   { EnterCriticalSection(m); }
static inline void mtx_unlock(mtx_t *m) { LeaveCriticalSection(m); }
static inline void mtx_destroy(mtx_t *m){ DeleteCriticalSection(m); }
#else
typedef pthread_mutex_t mtx_t;
static inline void mtx_init(mtx_t *m)   { pthread_mutex_init(m, NULL); }
static inline void mtx_lock(mtx_t *m)   { pthread_mutex_lock(m); }
static inline void mtx_unlock(mtx_t *m) { pthread_mutex_unlock(m); }
static inline void mtx_destroy(mtx_t *m){ pthread_mutex_destroy(m); }
#endif

// --- threads ---
typedef void *(*thr_fn_t)(void *);
#ifdef _WIN32
typedef HANDLE thr_t;
typedef struct { thr_fn_t fn; void *arg; } thr_arg_t;
static DWORD WINAPI thr_trampoline(LPVOID p) {
    thr_arg_t *ta = (thr_arg_t *)p;
    ta->fn(ta->arg);
    free(ta);
    return 0;
}
static inline int thr_create(thr_t *t, thr_fn_t fn, void *arg) {
    thr_arg_t *ta = (thr_arg_t *)malloc(sizeof(thr_arg_t));
    if (!ta) return -1;
    ta->fn = fn; ta->arg = arg;
    *t = CreateThread(NULL, 0, thr_trampoline, ta, 0, NULL);
    if (*t == NULL) { free(ta); return -1; }
    return 0;
}
static inline void thr_join(thr_t *t) { WaitForSingleObject(*t, INFINITE); CloseHandle(*t); }
#else
typedef pthread_t thr_t;
static inline int thr_create(thr_t *t, thr_fn_t fn, void *arg) {
    return pthread_create(t, NULL, fn, arg);
}
static inline void thr_join(thr_t *t) { pthread_join(*t, NULL); }
#endif

// --- auto-reset event (one pending wakeup) ---
#ifdef _WIN32
typedef HANDLE evt_t;
static inline void evt_init(evt_t *e)    { *e = CreateEvent(NULL, FALSE, FALSE, NULL); }
static inline void evt_signal(evt_t *e)  { SetEvent(*e); }
static inline void evt_wait(evt_t *e)    { WaitForSingleObject(*e, INFINITE); }
static inline void evt_destroy(evt_t *e) { CloseHandle(*e); }
#else
typedef struct { pthread_mutex_t m; pthread_cond_t c; int flag; } evt_t;
static inline void evt_init(evt_t *e) {
    pthread_mutex_init(&e->m, NULL);
    pthread_cond_init(&e->c, NULL);
    e->flag = 0;
}
static inline void evt_signal(evt_t *e) {
    pthread_mutex_lock(&e->m);
    e->flag = 1;
    pthread_cond_signal(&e->c);
    pthread_mutex_unlock(&e->m);
}
static inline void evt_wait(evt_t *e) {
    pthread_mutex_lock(&e->m);
    while (!e->flag) pthread_cond_wait(&e->c, &e->m);
    e->flag = 0;
    pthread_mutex_unlock(&e->m);
}
static inline void evt_destroy(evt_t *e) {
    pthread_mutex_destroy(&e->m);
    pthread_cond_destroy(&e->c);
}
#endif

#endif // HTTP_PLAT_DEFINED

#ifndef HTTP_NO_GZIP
#include "zlib/zlib.h"

// Gzip level used when serving static files
#define GZIP_COMPRESSION_LEVEL Z_DEFAULT_COMPRESSION
// Upper bound for an on-the-fly gzip output buffer
#define MAX_GZIP_OUTPUT (10 * 1024 * 1024)
#endif

// Default port, client, and worker limits
#define DEF_PORT        443
#define MAX_CLIENTS 256
#define NWORKERS    4
#define QSIZE       4096

// Default file and directory settings
#define DEF_ROOT "www";
#define DEF_CERT_FILE "localhost.crt"
#define DEF_KEY_FILE "localhost.key"
#define DEF_LOG_FILE "server.log"
#define DEF_UPLOAD_DIR "www/upload"
#define DEF_SERVER_NAME "nginx/1.25.2"
#define DEF_DOMAINS "localhost,127.0.0.1"
#define DEF_WWW_REDIRECT 1

// Timeouts in milliseconds (0 = no timeout)
#define TIMEOUT_IO          5000    // Per socket I/O operation
#define TIMEOUT_HANDSHAKE   10000   // Whole TLS handshake
#define TIMEOUT_TLS_POLL    500     // Extra TLS record read wait
#define TIMEOUT_FLIGHT      5000    // Full handshake flight
#define TIMEOUT_ACCEPT      500     // Accept-loop shutdown tick

// Security limits
#define DEF_MAX_BODY_MB  10                 // Default max request body in MB (0 = unlimited)
#define MAX_HEADER_SIZE  8192                // Max header size
#define MAX_URI_LENGTH   2048                // Max request URI
#define BLOCKED_PATHS_COUNT 7

// Connection states
#define S_IDLE     0
#define S_WORKING  1
#define S_SEND     2
#define S_CLOSE    3

// Capacity limits
#define HTTP_MAX_ROUTES 64
#define HTTP_MAX_ROUTES_INITIAL 16
#define HTTP_MAX_QUERY_INITIAL 8
#define HTTP_MAX_MPART_INITIAL 8
#define HTTP_MAX_SSL_CONNS 128

typedef struct http_server http_server_t;
typedef struct http_ctx http_ctx_t;

/* Logging callback installed via http_run(). Called by the http module for
 * every log message unless HTTP_NO_LOG is defined at compile time. If the
 * callback is NULL the module logs nothing. */
typedef void (*HttpLogFn)(int level, const char *fmt, ...);

/* Log level values passed to HttpLogFn. Kept compatible with log.h LogLevel
 * so an application callback can forward levels straight to its logger. */
#define HTTP_LOG_LEVEL_DEBUG 0
#define HTTP_LOG_LEVEL_INFO  1
#define HTTP_LOG_LEVEL_WARN  2
#define HTTP_LOG_LEVEL_ERROR 3

/* Default log output destination stored in http_server_t.log_output.
 * Kept compatible with log.h LogOutput so config can map 1:1. */
#define HTTP_LOG_OUTPUT_NONE    0
#define HTTP_LOG_OUTPUT_BOTH    1
#define HTTP_LOG_OUTPUT_CONSOLE 2
#define HTTP_LOG_OUTPUT_FILE    3

// Per-connection context
struct http_ctx{
    SOCKET fd;                       // Connected socket
    char   rb[16384]; size_t rlen;   // Raw request buffer and length
    char  *big; size_t big_cap;      // Dynamic request buffer for large bodies
    int    state;                    // Connection state
    char  *wb; size_t wlen,woff;     // Pending write buffer and cursor
    int    pending_write;            // Data buffered and ready to send
    int    is_https;                 // Connection uses TLS
    int    handshake_state;          // 1 after TLS handshake completes
    int    bad_record_count;         // Count of malformed TLS records
    int    timeout_io_ms;            // Per-socket I/O timeout (0 = none)
    unsigned long connect_tick;      // Accept timestamp
    unsigned long last_active;       // Last client data tick (idle reaper)
    int    req_done;                 // 1 when full request is read (reaper off)
    int    reaped;                   // Reaper already requested close
    const char *server_name;          // Server header value (default nginx/1.25.2)
    const char *domains;              // Comma-separated allowed Host domains
    int www_redirect;                 // 1 = 301 redirect www. -> bare domain (default), 0 = off
    void  *_ssl;                     // TLS object (SSL*) or NULL
};

/* Return the effective raw request buffer (dynamic or inline).
 * @param c Connection context.
 * @return Request buffer pointer. */
char *http_req_buf(http_ctx_t *c);

// Worker thread pool: workers pull queued http_ctx_t* connections
typedef struct {
    unsigned nt; thr_t *th;        // Worker count and thread handles
    http_ctx_t **q; int qh, qt, qs; // Ring queue of connections
    evt_t ev; mtx_t cs;            // Wakeup event and lock
} http_pool_t;

// A single multipart/form-data field
typedef struct {
    const char *name;         // Field name
    const char *filename;     // Original filename (file fields)
    const char *content_type; // Field content type
    void *data;               // Field payload
    size_t data_len;          // Payload length
} http_multipart_field_t;

// Parsed multipart form holding an array of fields
typedef struct {
    http_multipart_field_t *fields;  // Field array
    int count;                        // Number of parsed fields
    int capacity;                     // Allocated slots
} http_multipart_form_t;

// A single query-string parameter
typedef struct {
    char *key;    // Decoded key
    char *value;  // Decoded value
} http_query_param_t;

// Parsed query string holding key-value pairs
typedef struct {
    http_query_param_t *params;  // Parameter array
    int count;                    // Number of parameters
    int capacity;                 // Allocated slots
} http_query_string_t;

// Registered route: method+path dispatched to a handler
typedef struct {
    const char *method;   // HTTP method; "" or NULL matches any
    const char *path;     // Request path
    int (*handler)(http_server_t *http, http_ctx_t *c, const char *method, const char *uri,
                   const char *body, size_t body_len);  // Request handler
} http_route_entry_t;

// Route table
typedef struct {
    http_route_entry_t *entries;  // Route array
    int count;                     // Number of routes
    int capacity;                  // Allocated slots
} http_router_t;

// WebSocket frame opcodes
typedef enum {
    HTTP_WS_OPCODE_TEXT     = 0x1,
    HTTP_WS_OPCODE_BINARY   = 0x2,
    HTTP_WS_OPCODE_CLOSE    = 0x8,
    HTTP_WS_OPCODE_PING     = 0x9,
    HTTP_WS_OPCODE_PONG     = 0xA
} http_ws_opcode_t;

// Parsed WebSocket frame
typedef struct {
    int is_masked;               // Frame payload is client-masked
    uint64_t payload_len;        // Payload length
    unsigned char mask_key[4];   // Mask key
    unsigned char *payload;      // Pointer into the read buffer
    size_t payload_len_total;    // Total payload length
} http_ws_frame_t;

// Legacy TLS connection buffer (reserved)
typedef struct {
    SOCKET fd;                     // Socket
    SSL *ssl;                      // TLS object
    int active;                    // Connection in use
    uint8_t recv_buf[TLS_RSA_MAX_BUFFER];  // Incoming data buffer
    int recv_len;                           // Incoming data length
    uint8_t send_buf[TLS_RSA_MAX_BUFFER];   // Outgoing data buffer
    int send_len;                           // Outgoing data length
    int send_offset;                        // Outgoing cursor
} http_ssl_conn_t;

// HTTP server instance
struct http_server{
    int port;                        // Listening port
    const char *root;                // Document root
    const char *upload_dir;          // Directory for /api/upload files
    bool ssl_use;                    // Enable TLS
    int max_clients;                 // Max simultaneous connections
    int timeout_io_ms;               // Per-socket I/O timeout (0 = none)
    int timeout_handshake_ms;        // TLS handshake timeout (0 = none)
    int timeout_tls_poll_ms;         // Extra TLS read wait (0 = none)
    int timeout_flight_ms;           // Handshake flight timeout (0 = none)
    int timeout_accept_ms;           // Accept-loop tick (0 = none)
    int worker_threads;              // Thread pool size
    int max_body_mb;                 // Max request body in MB (0 = unlimited)
    const char *cert_file;           // TLS certificate path
    const char *key_file;            // TLS private key path
    const char *log_file;            // Log file path
    int log_output;                  // LogOutput destination
    int log_level;                   // LogLevel threshold
    const char *server_name;         // Server header value (default nginx/1.25.2)
    const char *domains;             // Comma-separated allowed Host domains
    int www_redirect;                // 1 = 301 redirect www. -> bare domain (default), 0 = off
    http_router_t router;            // Registered routes
    HttpLogFn log_fn;                // Logging callback (http_run) or NULL
    volatile int running;            // Server is running
    volatile int shutdown;           // Stop requested
    SOCKET listen_fd;                // Listening socket
    SSL_CTX *ssl_ctx;                // TLS context
    http_ssl_conn_t ssl_conns[HTTP_MAX_SSL_CONNS];  // Legacy TLS buffers
    http_ctx_t *ctx[MAX_CLIENTS];    // Connection table
    mtx_t ctx_lock;                  // Protects ctx[] (accept/reaper/workers)
    thr_t reaper;                    // Idle-reaper thread handle
    int reaper_on;                   // Reaper thread is running
    http_pool_t pool;                // Worker pool
    long total_req;                  // Total requests
    long status_2xx;                 // 2xx responses
    long status_3xx;                 // 3xx responses
    long status_4xx;                 // 4xx responses
    long status_5xx;                 // 5xx responses
    time_t start_time;               // Server start time
};

/* Create and allocate an HTTP server instance with default settings.
 * @return Allocated server, or NULL on allocation failure. */
http_server_t *http_init();

/* Release an HTTP server instance and stop all threads.
 * @param http Server to release. */
void http_free(http_server_t *http);

/* Register a route handler for an HTTP method and path.
 * @param http Server instance.
 * @param method HTTP method, or "" for any.
 * @param path Request path to match.
 * @param handler Callback invoked for matching requests. */
void http_route(http_server_t *http, const char *method, const char *path,
                int (*handler)(http_server_t *http, http_ctx_t *c, const char *method, const char *uri,
                               const char *body, size_t body_len));

/* Start the server: listen, spawn the thread pool, run the accept loop.
 * @param http Server instance.
 * @param log Logging callback, or NULL to disable module logging.
 * @return 0 on success, -1 on failure. */
int http_run(http_server_t *http, HttpLogFn log);

/* Check whether the client Accept-Encoding header allows gzip.
 * @param raw Raw request headers.
 * @param rlen Header length.
 * @return 1 if gzip is accepted, 0 otherwise. */
#ifndef HTTP_NO_GZIP
int http_client_accepts_gzip(const char *raw, size_t rlen);
#endif

/* Detect path traversal attempts in a path.
 * @param path Path to inspect.
 * @return 1 if traversal is detected, 0 otherwise. */
int http_check_path_traversal(const char *path);

/* Check whether a path matches a blocked pattern.
 * @param path Path to inspect.
 * @return 1 if blocked, 0 otherwise. */
int http_is_blocked_path(const char *path);

/* Validate body and header sizes against configured limits.
 * @param body_len Body length.
 * @param header_len Header length.
 * @return 1 if the body is too large, 2 if the header is too large, else 0. */
int http_check_size_limits(size_t body_len, size_t header_len, size_t max_body_bytes);

/* Increment the status-code category counter for a response.
 * @param http Server instance.
 * @param http_status Response status code. */
void http_update_status_stats(http_server_t *http, int http_status);

/* Print server statistics to the configured log output.
 * @param http Server instance. */
void http_print_statistics(http_server_t *http);

/* Initialize an empty query string parser.
 * @param qs Parser to initialize. */
void http_query_init(http_query_string_t *qs);

/* Free all memory held by a query string parser.
 * @param qs Parser to destroy. */
void http_query_destroy(http_query_string_t *qs);

/* Parse a URL-encoded query string into key-value pairs.
 * @param qs Parser to fill.
 * @param query_string Query string (without the leading '?').
 * @return Number of parameters parsed. */
int http_query_parse(http_query_string_t *qs, const char *query_string);

/* Retrieve the value for a key in a parsed query string.
 * @param qs Parsed query string.
 * @param key Parameter name.
 * @return The value, or NULL if not found. */
const char *http_query_get(const http_query_string_t *qs, const char *key);

/* Check whether a key exists in a parsed query string.
 * @param qs Parsed query string.
 * @param key Parameter name.
 * @return 1 if present, 0 otherwise. */
int http_query_has(const http_query_string_t *qs, const char *key);

/* Parse a multipart/form-data body into fields.
 * @param form Form to fill.
 * @param body Request body.
 * @param body_len Body length.
 * @param boundary Multipart boundary string.
 * @return Number of fields parsed. */
int http_multipart_parse(http_multipart_form_t *form, const char *body, size_t body_len, const char *boundary);

/* Free all memory held by a multipart form.
 * @param form Form to destroy. */
void http_multipart_destroy(http_multipart_form_t *form);

/* Retrieve a field by name from a parsed multipart form.
 * @param form Parsed form.
 * @param name Field name.
 * @return The field, or NULL if not found. */
const http_multipart_field_t *http_multipart_get(const http_multipart_form_t *form, const char *name);

/* Check whether a multipart field represents an uploaded file.
 * @param f Field to inspect.
 * @return 1 if it has a filename, 0 otherwise. */
int http_multipart_is_file(const http_multipart_field_t *f);

/* Perform the WebSocket upgrade handshake on a connection.
 * @param c Connection context.
 * @param raw_hdr Raw request headers.
 * @param hdr_len Header length.
 * @return 1 on success, 0 on failure. */
int http_ws_handshake(http_ctx_t *c, const char *raw_hdr, size_t hdr_len);

/* Read a WebSocket frame from a socket buffer.
 * @param fd Connected socket.
 * @param rb Read buffer.
 * @param rlen Buffer length.
 * @param off Offset of the frame start.
 * @param frame Frame to fill.
 * @return Total frame size, or 0 if incomplete. */
int http_ws_read_frame(SOCKET fd, unsigned char *rb, size_t rlen, size_t off, http_ws_frame_t *frame);

/* Send a WebSocket text frame.
 * @param c Connection context.
 * @param text Text payload. */
void http_ws_send_text(http_ctx_t *c, const char *text);

/* Send a WebSocket binary frame.
 * @param c Connection context.
 * @param data Binary payload.
 * @param len Payload length. */
void http_ws_send_binary(http_ctx_t *c, const unsigned char *data, size_t len);

/* Send a WebSocket close frame.
 * @param c Connection context.
 * @param code Close status code.
 * @param reason Close reason text. */
void http_ws_send_close(http_ctx_t *c, int code, const char *reason);

/* Send a WebSocket pong frame echoing a payload.
 * @param c Connection context.
 * @param payload Pong payload.
 * @param len Payload length. */
void http_ws_send_pong(http_ctx_t *c, const unsigned char *payload, size_t len);

/* Write a WebSocket frame header.
 * @param c Connection context.
 * @param fin FIN flag.
 * @param opcode Frame opcode.
 * @param payload_len Payload length. */
void http_ws_write_frame_header(http_ctx_t *c, unsigned char fin, unsigned char opcode, uint64_t payload_len);

/* Send the SSE response headers.
 * @param c Connection context. */
void http_sse_init_response(http_ctx_t *c);

/* Read up to len bytes from a connection (TLS-aware).
 * @param c Connection context.
 * @param buf Destination buffer.
 * @param len Maximum bytes to read.
 * @return Bytes read, or -1 on error/disconnect. */
int http_sock_read_data(http_ctx_t *c, char *buf, int len);

/* Send an SSE event.
 * @param c Connection context.
 * @param event Event name, or NULL.
 * @param data Event data.
 * @param id Event id, or NULL.
 * @param retry Retry hint, or NULL. */
void http_sse_send(http_ctx_t *c, const char *event, const char *data, const char *id, const char *retry);

/* Compare an HTTP method with a pattern (case-insensitive).
 * @param pattern Pattern; empty matches any method.
 * @param method Actual method.
 * @return 1 if they match, 0 otherwise. */
int http_method_matches(const char *pattern, const char *method);

/* Append chunked-encoded data to the write buffer.
 * @param c Connection context.
 * @param d Data to encode.
 * @param dl Data length. */
void http_write_chunked(http_ctx_t *c, const char *d, size_t dl);

/* Get the MIME type for a file extension.
 * @param p File name or path.
 * @return MIME type string. */
const char *http_mime_type(const char *p);

/* Serve a static file from the document root.
 * @param http Server instance.
 * @param c Connection context.
 * @param rel Path relative to the root. */
void http_sfile(http_server_t *http, http_ctx_t *c, const char *rel);

/* Parse an HTTP request and dispatch it to the matching handler.
 * @param http Server instance.
 * @param c Connection context.
 * @param raw Raw request text.
 * @param rlen Request length. */
void http_do_parse(http_server_t *http, http_ctx_t *c, const char *raw, size_t rlen);

/* Register a newly accepted client socket with the server (reserved).
 * @param http Server instance.
 * @param fd Accepted socket. */
void http_add_client(http_server_t *http, SOCKET fd);

/* Flush the connection write buffer to the socket.
 * @param http Server instance.
 * @param c Connection context. */
void http_send_buf(http_server_t *http, http_ctx_t *c);

/* Dispatch the request to a matched route handler or static file.
 * @param http Server instance.
 * @param c Connection context.
 * @return 1 when handled. */
int http_dispatch_handler(http_server_t *http, http_ctx_t *c);

/* Send a JSON response.
 * @param http Server instance.
 * @param c Connection context.
 * @param status HTTP status code.
 * @param json_body JSON body text. */
void http_send_json_response(http_server_t *http, http_ctx_t *c, int status, const char *json_body);

/* Send a plain text response.
 * @param http Server instance.
 * @param c Connection context.
 * @param status HTTP status code.
 * @param text Body text. */
void http_send_text_response(http_server_t *http, http_ctx_t *c, int status, const char *text);

/* Send an HTML response.
 * @param http Server instance.
 * @param c Connection context.
 * @param status HTTP status code.
 * @param html Body HTML. */
void http_send_html_response(http_server_t *http, http_ctx_t *c, int status, const char *html);

/* Extract the Content-Type value from raw request headers.
 * @param raw_hdr Raw request headers.
 * @return The value, or NULL if absent. */
const char *http_get_content_type(const char *raw_hdr);

/* HTML-escape a string into a destination buffer.
 * @param dst Destination buffer.
 * @param dst_size Destination capacity.
 * @param s Source string. */
void http_html_escape_str(char *dst, size_t dst_size, const char *s);

#ifdef __cplusplus
}
#endif

#endif // HTTP_H