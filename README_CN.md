# crypery

> [English version](README.md)

> [Russian version](README_RU.md)

## 项目简介

**crypery** - 一个纯 C/C++ 编写的网络协议栈，由四个模块组成：TLS 1.2/1.3 加密库、OpenSSL 兼容的 SSL 封装层、HTTPS 服务器和 HTTPS 客户端。

主要特点：

- **所有加密算法均从零实现** - 不依赖任何外部加密库。唯一的可选依赖是用于 gzip 压缩的 zlib（可通过 `HTTP_NO_GZIP` 标志关闭）。
- **可移植性** - 支持 Windows（MinGW、Winsock）和类 Unix 系统（BSD 套接字、pthreads）。
- **完整链路**：从底层加密（AES-GCM、RSA、ECDH）到开箱即用的 HTTP 服务器和 HTTP 客户端。

## 模块依赖关系图

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

## 模块说明

### tls

基础加密层。TLS 1.2 和 TLS 1.3 协议的纯 C/C++ 实现，内置一组原语：

- 对称加密 AES-128-GCM；
- 哈希 SHA-256、MAC HMAC-SHA256、密钥派生 HKDF-SHA256；
- 非对称加密：RSA-2048（PKCS#1 v1.5 签名和 RSASSA-PSS）、P-256（secp256r1）和 X25519 曲线上的 ECDH；
- 自签名 X.509 证书的生成与解析（DER/PEM），包括 PEM 文件加载；
- TLS 连接上下文：握手（客户端/服务器、自动选择版本）、应用数据加解密、SNI、对端证书校验、close_notify；
- 线程安全：随机数生成（xorshift128）受锁保护，支持在线程池中并行进行握手。

### ssl

内置 TLS 实现之上的 OpenSSL 兼容 API 层。目标是让为 OpenSSL 编写的代码无需修改即可运行：

- 与 OpenSSL 兼容的上下文和连接类型；
- 从 PEM 文件加载证书和私钥，校验密钥与证书是否匹配；
- 服务器端和客户端握手（TLS 1.2/1.3）；
- 基于套接字的加密读写；
- 可配置的超时：I/O 操作、整个握手、等待 TLS 记录写入、分片报文重组；
- 对端证书校验模式；
- 平台适配层：Windows 上使用 Winsock，POSIX 上使用 BSD 套接字。

### http

自包含的 HTTP/1.1 服务器库，构建于内置 TLS 协议栈之上：

- 按方法和路径进行请求路由，支持自定义处理器；
- 从根目录分发静态文件，自动识别 MIME 类型；
- gzip 压缩：分发预压缩的 `.gz` 文件以及通过 zlib 实时压缩（可通过 `HTTP_NO_GZIP` 关闭）；
- WebSocket（RFC 6455）：连接升级、帧的读取与发送（文本、二进制、close、ping/pong）；
- Server-Sent Events（SSE）；
- query 字符串解析（URL 解码）和 multipart/form-data（包括文件上传）；
- 安全性：防 path traversal 攻击、屏蔽敏感路径（`.git`、`.env`、`config*` 等）、按域名列表校验 Host 头、请求体和请求头大小限制；
- 工作线程池 + 连接环形队列，阻塞式 accept 循环；
- 根据首字节自动识别 TLS/HTTP（0x16 → TLS，否则为 HTTP 并返回 426）；
- 统计信息：按状态码类别统计请求数、运行时长、req/s；
- 自带平台适配层（套接字、字符串、线程、互斥锁、事件）- 模块不依赖外部 compat 头文件。

### url

自包含的 HTTP/HTTPS 客户端库，构建于内置 TLS 协议栈之上：

- 绝对 URL 解析：http/https、显式端口、userinfo、片段、IPv6 字面量；
- 执行 HTTP/1.1 请求（GET、POST、HEAD 等），支持自定义请求头、请求体、Content-Type、Range；
- 读取响应：状态行、请求头、按 Content-Length、chunked transfer encoding 或直到 EOF 读取响应体；
- 重定向处理（301/302/303/307/308），遵循 RFC 7231 的方法语义，并限制跳转次数；
- 构建 multipart/form-data 请求体（字段和文件、boundary 生成、按扩展名识别 MIME）；
- 传输层：DNS 解析、带超时的连接、TLS 握手（SNI、可选跳过证书校验）、缓冲读写；
- 与 curl 约定兼容的错误码；
- 可选的详细日志回调（可通过 `URL_NO_LOG` 关闭）。

## 主要使用的技术

- **语言**：纯 C/C++，无外部依赖（zlib 为可选）。
- **协议**：TLS 1.2、TLS 1.3、HTTP/1.1、HTTPS、WebSocket（RFC 6455）、SSE、chunked transfer encoding。
- **加密**：AES-128-GCM、SHA-256、HMAC-SHA256、HKDF-SHA256、RSA-2048（PKCS#1 v1.5、RSASSA-PSS）、ECDH P-256（secp256r1）、X25519、X.509（DER/PEM）、SHA-1（仅用于 WebSocket 握手）。
- **网络层**：Winsock2（Windows）/ BSD 套接字（POSIX）、`select()` 用于超时、`SO_RCVTIMEO`、`getaddrinfo` 用于 DNS。
- **线程**：WinAPI 线程（Windows）/ pthreads（POSIX）、工作线程池、临界区 / 互斥锁、自动重置事件。
- **压缩**：通过 zlib 实现 gzip（可选）。
- **API 兼容性**：OpenSSL（SSL_CTX/SSL）和 curl（url_*）。

## 使用示例

### tls

生成密钥、自签名证书并进行握手：

```c
#include "tls.h"

/* 生成 RSA-2048 密钥和自签名证书 */
RSAKey key;
tls_rsa_generate_key(&key);

uint8_t cert[TLS_RSA_MAX_CERT_SIZE];
int cert_len = sizeof(cert);
tls_generate_self_signed_cert(&key, cert, &cert_len);

/* 自动选择 TLS 版本的服务器上下文 */
TLSContext ctx;
tls_init_context_auto(&ctx, 1);
tls_set_rsa_key(&ctx, &key);
tls_set_certificate(&ctx, cert, cert_len);

/* 分步握手：传入接收到的数据，得到要发送的数据 */
uint8_t in[TLS_RSA_MAX_BUFFER], out[TLS_RSA_MAX_BUFFER];
int in_len = 0, out_len = 0;
int ret = tls_handshake_step(&ctx, in, in_len, out, &out_len);
/*... 发送 out 并用新的 in 重复调用，直到握手完成... */

/* 加密发送和接收应用数据 */
uint8_t data[] = "hello";
ret = tls_send_application_data(&ctx, data, sizeof(data) - 1, out, &out_len);

uint8_t plain[TLS_RSA_MAX_BUFFER];
int plain_len = sizeof(plain);
ret = tls_receive_application_data(&ctx, in, in_len, plain, &plain_len);

/* 正常关闭连接 */
tls_close(&ctx, out, &out_len);
```

### ssl

OpenSSL 兼容的服务器：

```c
#include "ssl.h"

/* 上下文：从 PEM 加载证书和密钥 */
SSL_CTX *ctx = SSL_CTX_new();
SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM);
SSL_CTX_check_private_key(ctx);

/* 超时（毫秒） */
ssl_set_io_timeout(ctx, 5000);
ssl_set_handshake_timeout(ctx, 10000);

/* 在接受到的套接字上建立连接 */
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

客户端类似：用 `SSL_connect()` 代替 `SSL_accept()`。

### http

带 API 路由和静态文件分发的服务器：

```c
#include "http.h"

/* 路由处理器 */
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
    http->root = "www";
    http->ssl_use = true;
    http->cert_file = "localhost.crt";
    http->key_file = "localhost.key";

    http_route(http, "GET", "/api/info", handle_info);

    http_run(http, my_log_cb);   /* NULL - 关闭模块日志 */
    http_free(http);
    return 0;
}
```

对未注册路由的路径的请求，会自动由 `http->root` 下的静态文件分发处理。

### url

执行 HTTPS 请求：

```c
#include "url.h"

UrlCtx *ctx = url_init();
ctx->verbose = 1;                          /* 控制台详细输出 */
ctx->follow_redirects = 1;                 /* 跟随重定向 */

url_set_header(ctx, "X-Api-Key", "123");   /* 自定义请求头 */
url_set_data(ctx, "a=1&b=2", 7);           /* POST 请求体 */
url_set_content_type(ctx, "application/x-www-form-urlencoded");

char *data = url_run(ctx, "https://example.com", "POST", NULL);
if (data) {
    printf("status: %d\n", url_status(ctx));
    printf("%s", data);
    free(data);                            /* 缓冲区由 url_run() 分配 */
} else {
    printf("error: %d\n", ctx->last_error);
}
url_free(ctx);
```

## License

GNU AGPL v3 (Affero GPL)
