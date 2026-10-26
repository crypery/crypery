/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * url.h - public interface of the self-contained HTTP/HTTPS client library.
 *
 * A small curl-like library wrapping URL parsing, HTTP/1.1 requests, chunked
 * transfer decoding, multipart form bodies, redirect handling and the bundled
 * TLS stack (ssl.c + tls.c). It does NOT parse command-line arguments; that is
 * the job of the application (curl-ex.c).
 *
 * Typical use:
 *
 *     UrlCtx *ctx = url_init();                 // request context
 *     ctx->verbose = 1;                         // console log on/off
 *     url_set_header(ctx, "X-Api-Key", "123");  // custom headers if needed
 *     url_set_data(ctx, "a=1&b=2", 7);          // POST body if needed
 *     url_set_content_type(ctx, "application/x-www-form-urlencoded");
 *     char *data = url_run(ctx, "https://example.com", "POST", NULL);
 *     if (data) { printf("%s", data); free(data); }
 *
 *     // Download a large file straight to disk (never to the console):
 *     // bodies up to 10 MB use the classic in-memory path, larger (or
 *     // size-unknown / chunked) bodies are streamed to the file chunk by
 *     // chunk - I/O limits apply per chunk, so long downloads keep running
 *     // as long as data keeps arriving.
 *     size_t saved = 0;
 *     url_download_file(ctx, "https://example.com/model.bin",
 *                       "model.bin", NULL, &saved);
 *
 *     url_free(ctx);
 *
 * All public functions are prefixed with url_ (never url_url_...). The buffer
 * returned by url_run() must be freed by the caller with free(). Any memory
 * assigned to ctx->data is owned by the context and freed by url_free().
 */

#ifndef URL_H
#define URL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* C++ linkage guard: allow these headers to be included from C++ code so the
 * url_* functions link against a C-compiled url.c without name mangling. */
#ifdef __cplusplus
extern "C" {
#endif

// ============================ Constants ============================

// Maximum host name length in bytes, including the NUL terminator.
#define URL_MAX_HOST    256
// Maximum URL path (and query) length in bytes, including the NUL terminator.
#define URL_MAX_PATH    2048
// Maximum number of headers in a HeaderList (per request or response).
#define URL_MAX_HEADERS 64
// Maximum number of -d style data chunks kept in Options.
#define URL_MAX_DATA    16
// Maximum number of -F style form fields kept in Options.
#define URL_MAX_FORMS   16
// Default maximum number of redirects followed by url_run().
#define URL_MAX_REDIRS  50

/* Error codes stored in ctx->last_error after a failed url_run() call.
 * 0 (URL_OK) means no error. The numeric values follow the well-known curl
 * exit-code conventions where a matching code exists. */
#define URL_OK                 0   // no error
#define URL_ERR_INVALID_URL    1   // URL rejected (malformed or unsupported)
#define URL_ERR_INIT           2   // network/library initialization failed
#define URL_ERR_CONNECT        7   // failed to connect to the host
#define URL_ERR_READ_BODY     18   // failed to read the response body
#define URL_ERR_TLS           35   // TLS handshake failed
#define URL_ERR_MAX_REDIR     47   // too many redirects followed
#define URL_ERR_SEND          55   // failed to send the request
#define URL_ERR_RECV          56   // no HTTP response received
#define URL_ERR_WRITE_FILE    23   // failed to open/write the output file
#define URL_ERR_BUILD_REQUEST 98   // failed to build the request

/* Compile-time switch: define URL_NO_LOG before including url.h (e.g. with
 * -DURL_NO_LOG) to strip all log callback invocations from url.c. The log
 * format strings and their argument setup are then removed from the binary,
 * which reduces its size. Default: not defined, logging fully active. */
#ifdef URL_NO_LOG
#define URL_LOGGING 0
#else
#define URL_LOGGING 1
#endif

// ============================ Structures ============================

// A parsed absolute URL (scheme://host[:port]/path[?query][#fragment]).
typedef struct {
    int is_ssl;                 // 1 = https, 0 = http
    char host[URL_MAX_HOST];    // host name or IPv6 literal without brackets
    int port;                   // 443 for https, 80 for http unless overridden
    char path[URL_MAX_PATH];    // includes the query string, no fragment
} UrlInfo;

// One HTTP header: lowercase name + value.
typedef struct {
    char name[64];              // header name, stored lowercased
    char value[2048];           // header value, whitespace trimmed
} Header;

// Ordered list of headers.
typedef struct {
    Header h[URL_MAX_HEADERS];  // fixed-size array of headers
    int n;                      // number of headers currently stored
} HeaderList;

// Parsed response status line + headers.
typedef struct {
    int status;                 // HTTP status code, e.g. 200
    char version[16];           // protocol version, e.g. "1.1"
    char reason[128];           // reason phrase, e.g. "OK"
    HeaderList headers;         // response headers
} ResponseHead;

/* HTTP request context: request parameters and the results of the last
 * url_run() call. Set the parameters directly or via the url_set_* helpers. */
typedef struct {
    // --- request parameters ---
    HeaderList headers;         // custom request headers
    char user_agent[256];       // empty => default "curl/8.6.0"
    char content_type[256];     // empty => not sent
    char *data;                 // request body; malloc'ed, freed by url_free()
    size_t data_len;            // byte length of ctx->data
    char range[64];             // empty => no Range header
    int follow_redirects;       // 1 = follow Location redirects
    int max_redirs;             // redirect limit for follow_redirects
    int verbose;                // 1 = console log enabled
    int silent;                 // 1 = suppress error messages
    int insecure;               // 1 = skip TLS certificate verification
    int include_headers;        // 1 = returned data includes the response head
    long connect_timeout_ms;    // -1 if unset
    int connect_timeout_set;
    bool use_cook;              // 1 = use the shared cookie jar for requests
    char *cook_file;            // cookie jar file; NULL = memory only. When set,
                                // the jar is loaded from it on the first url_run()
                                // and saved back on every jar change.

    // --- results of the last url_run() ---
    int last_status;            // HTTP status, 0 if no response
    int last_error;             // error code (URL_ERR_*), 0 if none
    ResponseHead last_head;     // parsed status line + headers
    size_t result_len;          // byte length of the returned string
} UrlCtx;

// ============================ Functions ============================

/* Create a request context with default parameters.
 *
 * Defaults: no custom headers, default User-Agent, no body, no Range header,
 * redirects NOT followed (follow_redirects = 0), max_redirs = URL_MAX_REDIRS,
 * no console logging (verbose = 0, silent = 0), TLS verification on
 * (insecure = 0), response head excluded (include_headers = 0), connect
 * timeout unset, cookie jar disabled (use_cook = false, cook_file = NULL).
 *
 * @return Pointer to a new UrlCtx on success, NULL on allocation failure.
 *         The context must be freed with url_free().
 */
UrlCtx *url_init(void);

/* Free a request context and all memory it owns.
 *
 * Releases ctx->data (if set) and the context itself.
 *
 * @param ctx Context created by url_init(); NULL is safely ignored.
 */
void url_free(UrlCtx *ctx);

/* Log callback used by url_run().
 *
 * url_run() reports verbose progress lines and error messages by calling this
 * function (respecting ctx->verbose / ctx->silent). It receives printf-style
 * format strings together with their arguments; the callback is responsible
 * for formatting and emitting the text (e.g. vfprintf to stderr). Passing
 * NULL disables all logging.
 *
 * To reduce the size of the binary, compile with URL_NO_LOG defined: every
 * log callback invocation is then removed at compile time and the format
 * strings never end up in the binary. url_run() keeps the UrlLogFn parameter
 * for API compatibility; when URL_NO_LOG is defined the callback is simply
 * never invoked, regardless of the value passed in.
 */
typedef void (*UrlLogFn)(const char *fmt, ...);

/* Perform an HTTP(S) request and return the response body as a string.
 *
 * Connects to the host, performs the TLS handshake when the URL is https,
 * sends the request built from the context parameters (headers, body,
 * content type, range), reads the response status/headers/body, decodes
 * chunked transfer encoding and follows redirects when ctx->follow_redirects
 * is set (up to ctx->max_redirs). After the call the response metadata is
 * available in ctx->last_status, ctx->last_head and via url_status() /
 * url_response_header().
 *
 * @param ctx    Request context with the parameters; created by url_init().
 *               Must not be NULL.
 * @param url    Absolute URL such as "https://example.com/path?q=1".
 *               Must not be NULL.
 * @param method HTTP method, e.g. "GET", "POST", "HEAD". Must not be NULL.
 * @param log    Log callback invoked for verbose progress lines and error
 *               messages (see UrlLogFn). Pass NULL to disable logging.
 * @return A NUL-terminated malloc'ed string with the response body (plus the
 *         response head "HTTP/1.1 200 OK\r\n...\r\n\r\n" prepended when
 *         ctx->include_headers is set), or NULL on failure (ctx->last_error
 *         then contains an error code from the URL_ERR_* constants). The
 *         caller must free() the returned
 *         buffer. The byte length is stored in ctx->result_len.
 */
char *url_run(UrlCtx *ctx, const char *url, const char *method, UrlLogFn log);

/* Download a URL and save the response body to a local file (never to the
 * console). Performs a GET request with the context parameters (headers,
 * redirects, timeouts, Range) and stores the response body at `path`:
 *  - a body with a known size of at most 10 MB is fetched the classic way
 *    (into memory, exactly as url_run does) and written to the file;
 *  - a larger, size-unknown or chunked body is streamed to disk chunk by
 *    chunk, so multi-gigabyte files do not need to fit in RAM.
 *
 * I/O limits apply to the chunks, not to the connection as a whole: every
 * read operation gets a fresh timeout window (io_timeout) and the transfer
 * is retried while the data-less gap stays below a bounded idle limit
 * (15..60 s), so a long download runs as long as data keeps arriving and
 * only a silent (dead) link fails.
 *
 * An existing file is replaced; with a Range header set (url_set_range) and
 * a 206 response the received part is appended to the existing file
 * (resume). When ctx->verbose is set, throttled progress lines are routed
 * through the log callback.
 *
 * @param ctx       Request context (created by url_init()); must not be NULL.
 * @param url       Absolute URL to download; must not be NULL.
 * @param path      Local file path to write to; must not be NULL or empty.
 * @param log       Log callback (same semantics as url_run); NULL disables it.
 * @param bytes_out Optional; receives the number of bytes written to the file.
 * @return 0 on success, -1 on failure (ctx->last_error then holds a URL_ERR_*
 *         code, e.g. URL_ERR_WRITE_FILE for disk errors).
 */
int url_download_file(UrlCtx *ctx, const char *url, const char *path, UrlLogFn log,
                      size_t *bytes_out);

// --- request parameter helpers ---

/* Add or replace a request header.
 *
 * The name is stored lowercased; supplying the same name again replaces the
 * previous value. These headers override the built-in defaults (Host,
 * User-Agent, Accept, Content-Type, Content-Length, Range, Connection) when
 * they share a name.
 *
 * @param ctx   Request context; must not be NULL.
 * @param name  Header name, e.g. "X-Api-Key". Must not be NULL.
 * @param value Header value, e.g. "secret". Must not be NULL; surrounding
 *              whitespace is trimmed.
 */
void url_set_header(UrlCtx *ctx, const char *name, const char *value);

/* Set the User-Agent request header.
 *
 * @param ctx Request context; must not be NULL.
 * @param ua  User-Agent string to send; an empty string or NULL restores the
 *            default "curl/8.6.0".
 */
void url_set_user_agent(UrlCtx *ctx, const char *ua);

/* Copy `len` bytes as the request body (POST data).
 *
 * The previous body (if any) is replaced and freed. The data is copied into
 * the context, so the caller keeps ownership of `data`. To send no body,
 * pass NULL or len == 0.
 *
 * @param ctx  Request context; must not be NULL.
 * @param data Pointer to the body bytes to send; may be NULL.
 * @param len  Number of bytes to copy from `data`.
 */
void url_set_data(UrlCtx *ctx, const char *data, size_t len);

/* Set the Content-Type request header.
 *
 * This header is only sent when a request body is present.
 *
 * @param ctx Request context; must not be NULL.
 * @param ct  MIME type, e.g. "application/json"; NULL or "" clears it.
 */
void url_set_content_type(UrlCtx *ctx, const char *ct);

/* Set the Range request header.
 *
 * @param ctx   Request context; must not be NULL.
 * @param range Range value, e.g. "bytes=100-"; NULL or "" clears it.
 */
void url_set_range(UrlCtx *ctx, const char *range);

// --- response helpers ---

/* HTTP status code of the last response.
 *
 * @param ctx Request context; may be NULL (returns 0).
 * @return The status code of the last url_run() response, e.g. 200, or 0 if
 *         no request has completed yet or ctx is NULL.
 */
int url_status(const UrlCtx *ctx);

/* Header value of the last response.
 *
 * @param ctx  Request context; may be NULL (returns NULL).
 * @param name Header name to look up, matched case-insensitively.
 * @return The header value from the last response, or NULL if absent.
 */
const char *url_response_header(const UrlCtx *ctx, const char *name);

// --- URL helpers ---

/* Split an absolute URL into its components.
 *
 * Recognizes http:// and https://, strips userinfo (user:pass@) and the URL
 * fragment, and supports explicit ports and IPv6 literals ([::1]:8080).
 *
 * @param url Absolute URL to parse; must not be NULL.
 * @param u   Output structure to fill with scheme/host/port/path.
 * @return 0 on success, -1 on a malformed or unsupported URL.
 */
int url_parse(const char *url, UrlInfo *u);

/* Resolve a Location header against the current base URL.
 *
 * Handles absolute URLs, scheme-relative (//host/path) and root-relative
 * (/path) locations as well as plain relative paths.
 *
 * @param base   The current absolute URL, e.g. "https://example.com/a/b".
 * @param loc    The Location header value to resolve against `base`.
 * @param out    Output buffer for the resolved absolute URL.
 * @param outlen Size of `out` in bytes.
 */
void url_join(const char *base, const char *loc, char *out, size_t outlen);

/* Normalize a URL path: collapse "." and ".." segments (query/fragment kept
 * intact).  `path` may be "/a/../b?q" or "a/./b". */
void url_normalize_path(const char *path, char *out, size_t outlen);

/* URL-decode a string in place.
 *
 * Replaces every %XX escape with the corresponding byte; leaves all other
 * characters unchanged.
 *
 * @param s NUL-terminated string to decode in place; must not be NULL.
 */
void url_decode(char *s);

// ============================ Cookie jar ============================
// The cookie jar is a single process-wide list shared by every UrlCtx.
// Enable it per context with ctx->use_cook; when ctx->cook_file is not NULL
// the jar is loaded from that file on the first url_run() and saved back to
// it whenever the list changes (so a new application run picks the list up
// from the file). With ctx->cook_file == NULL the jar lives in memory only.

/* Parse one "Set-Cookie" header value received for `url` and store it in
 * the shared cookie jar (adding, updating or removing the entry, e.g. when
 * it expires). RFC 6265 basics: name=value, Domain, Path, Secure,
 * Max-Age, Expires.
 *
 * @param url        Request URL the header was received for.
 * @param set_cookie Raw Set-Cookie header value.
 */
void url_cookie_set_from_url(const char *url, const char *set_cookie);

/* Build the "Cookie:" header value for `url` from the shared jar.
 *
 * @param url Request URL to match against (host, path, scheme).
 * @return malloc'ed string (free with free()), or NULL if no cookie applies.
 */
char *url_cookie_header_for(const char *url);

/* Load the shared cookie jar from `file` (tab-separated lines:
 * domain, path, name, value, secure, expires). A missing or malformed file
 * leaves the current list untouched.
 *
 * @param file File name; if NULL the call does nothing.
 */
void url_cookie_load(const char *file);

/* Save the shared cookie jar to `file` (expired entries are dropped).
 *
 * @param file File name; if NULL the call does nothing.
 */
void url_cookie_save(const char *file);

/* Determine the remote file name.
 *
 * Uses the Content-Disposition filename first, otherwise the last segment of
 * the URL path (URL-decoded, query stripped), otherwise "index.html".
 *
 * @param u           Parsed URL; must not be NULL.
 * @param disposition Content-Disposition header value, or NULL to skip it.
 * @param out         Output buffer for the file name.
 * @param outlen      Size of `out` in bytes.
 * @return 0 on success, -1 if no name could be derived.
 */
int url_remote_name(const UrlInfo *u, const char *disposition, char *out, size_t outlen);

/* Extract filename= from a Content-Disposition header.
 *
 * @param cd     Content-Disposition header value, e.g.
 *               "attachment; filename=\"x.txt\"". Must not be NULL.
 * @param out    Output buffer for the extracted file name.
 * @param outlen Size of `out` in bytes.
 * @return 0 if a filename was found and written, -1 otherwise.
 */
int url_content_disposition_filename(const char *cd, char *out, size_t outlen);

// --- HTTP helpers ---

/* Parse the raw header block into a ResponseHead.
 *
 * @param raw    Raw bytes starting with "HTTP/1.1 200 OK\r\n...\r\n\r\n".
 * @param rawlen Number of bytes in `raw`.
 * @param rh     Output structure for status line + headers.
 * @return 0 on success, -1 if the status line is missing or invalid.
 */
int url_http_parse_status_and_headers(const char *raw, size_t rawlen, ResponseHead *rh);

/* Parse a hex chunk-size line, ignoring ";extensions".
 *
 * @param line The chunk header line, e.g. "1A" or "4;ext=1".
 * @return The decoded chunk size, or UINT64_MAX on error/empty input.
 */
uint64_t url_http_chunk_size(const char *line);

/* Decode a whole chunked body from memory.
 *
 * @param in      The raw chunked-encoded data (including chunk headers).
 * @param in_len  Number of bytes in `in`.
 * @param out     Output buffer for the decoded body.
 * @param out_max Capacity of `out` in bytes.
 * @param out_len Receives the number of decoded bytes on success.
 * @return 0 on success, -1 on malformed/truncated input or overflow.
 */
int url_http_chunked_decode(const char *in, size_t in_len, char *out, size_t out_max, size_t *out_len);

/* Build a multipart/form-data body from -F style arguments.
 *
 * Each form item has the form "name=value", "name=@file" or
 * "name=@file;type=mime". A random boundary is generated.
 *
 * @param forms    Array of form item strings.
 * @param n        Number of items in `forms`.
 * @param out      Receives a malloc'ed body string (caller frees it).
 * @param outlen   Receives the body length in bytes.
 * @param boundary Receives the generated boundary string.
 * @param bsz      Capacity of `boundary` in bytes (at least 48).
 * @return 0 on success, -1 on a malformed item or an unreadable file.
 */
int url_multipart_build(const char *forms[], int n, char **out, size_t *outlen,
                        char *boundary, size_t bsz);

/* Pick the method to use when following a redirect (RFC 7231 semantics).
 *
 * 301/302/303 switch any method except GET/HEAD to GET; 307/308 keep it.
 *
 * @param method The current HTTP method.
 * @param status The redirect status code (3xx).
 * @param out    Output buffer for the resulting method.
 * @param outlen Size of `out` in bytes.
 * @return 0 on success.
 */
int url_redirect_method(const char *method, int status, char *out, size_t outlen);

/* Append a header to a header list.
 *
 * The name is lowercased, the value is trimmed, and a duplicate name replaces
 * the previous value. Silently does nothing when the list is full.
 *
 * @param l     Header list to modify.
 * @param name  Header name; must not be NULL.
 * @param value Header value; must not be NULL.
 */
void url_header_add(HeaderList *l, const char *name, const char *value);

/* Look up a header in a header list.
 *
 * @param l    Header list to search.
 * @param name Header name, matched case-insensitively.
 * @return The header value, or NULL when absent.
 */
const char *url_header_get(const HeaderList *l, const char *name);

/* Serialize the full HTTP/1.1 request (headers + optional body).
 *
 * Built from the context headers/User-Agent plus the explicit content type,
 * range and body. The body is not decoded or modified.
 *
 * @param ctx          Request context providing headers and User-Agent.
 * @param u            Parsed URL (Host header, path, port).
 * @param method       HTTP method, e.g. "GET".
 * @param content_type MIME type, or NULL; enables Content-Length when set.
 * @param range        Range value, or NULL.
 * @param body         Request body bytes, or NULL.
 * @param body_len     Number of bytes in `body`.
 * @param out_len      Receives the length of the returned string.
 * @return A NUL-terminated malloc'ed request string; caller frees it.
 */
char *url_build_request(const UrlCtx *ctx, const UrlInfo *u, const char *method,
                        const char *content_type, const char *range,
                        const char *body, size_t body_len, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // URL_H
