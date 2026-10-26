# crypery

> [English version](README.md)

> [China version](README_CN.md)

## Описание проекта

**crypery** - сетевой стек на чистом C/CPP, состоящий из четырёх модулей: криптографическая библиотека TLS 1.2/1.3, OpenSSL-совместимый SSL-обёрточный слой, HTTPS-сервер и HTTPS-клиент.

Ключевые особенности:

- **Все криптоалгоритмы реализованы с нуля** - без внешних криптографических библиотек. Единственная опциональная зависимость - zlib для gzip-сжатия (отключается флагом `HTTP_NO_GZIP`).
- **Портативность** - работает на Windows (MinGW, Winsock) и Unix-подобных системах (BSD-сокеты, pthreads).
- **Полный цикл**: от низкоуровневой криптографии (AES-GCM, RSA, ECDH) до готовых HTTP-сервера и HTTP-клиента.

## Схема зависимостей модулей

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

## Описание модулей

### tls

Базовый криптографический слой. Чистая C/CPP-реализация протоколов TLS 1.2 и TLS 1.3 со встроенным набором примитивов:

- симметричное шифрование AES-128-GCM;
- хеширование SHA-256, MAC HMAC-SHA256, вывод ключей HKDF-SHA256;
- асимметричная криптография: RSA-2048 (подпись PKCS#1 v1.5 и RSASSA-PSS), ECDH на кривых P-256 (secp256r1) и X25519;
- генерация и разбор самоподписанных X.509-сертификатов (DER/PEM), включая загрузку PEM-файлов;
- контекст TLS-соединения: рукопожатие (клиент/сервер, автовыбор версии), шифрование и расшифровка данных приложения, SNI, проверка сертификата стороны, close_notify;
- потокобезопасность: генерация случайных чисел (xorshift128) защищена блокировкой, что позволяет вести параллельные рукопожатия в пуле потоков.

### ssl

OpenSSL-совместимый API-слой над встроенной реализацией TLS. Предназначен для того, чтобы код, написанный под OpenSSL, работал без изменений:

- типы контекста и соединения, совместимые с OpenSSL;
- загрузка сертификата и закрытого ключа из PEM-файлов, проверка соответствия ключа сертификату;
- серверное и клиентское рукопожатие (TLS 1.2/1.3);
- шифрованный ввод-вывод поверх сокета;
- настраиваемые таймауты: I/O-операция, всё рукопожатие, ожидание записи TLS-записи, сборка фрагментированных пакетов;
- режимы проверки сертификата стороны;
- платформенный шим: Winsock на Windows, BSD-сокеты на POSIX.

### http

Самодостаточная HTTP/1.1-библиотекв сервера, построенная на встроенном TLS-стеке:

- маршрутизация запросов по методу и пути с пользовательскими обработчиками;
- раздача статических файлов из корневой директории с определением MIME-типов: файлы до 10 МБ читаются целиком в память, большие файлы стримятся клиенту частями (каждое соединение держит свой `FILE*`, файл не блокируется; лимиты I/O применяются к отправленным частям, а не ко всей передаче);
- gzip-сжатие: раздача предсжатых `.gz`-файлов и сжатие <на лету> через zlib (отключается `HTTP_NO_GZIP`);
- WebSocket (RFC 6455): апгрейд соединения, чтение и отправка кадров (текст, бинарные данные, close, ping/pong);
- Server-Sent Events (SSE);
- разбор query-строки (URL-декодирование) и multipart/form-data (включая загрузку файлов);
- безопасность: защита от path traversal, блокировка чувствительных путей (`.git`, `.env`, `config*` и др.), валидация заголовка Host по списку доменов, лимиты размера тела и заголовков;
- пул рабочих потоков с кольцевой очередью соединений, блокирующий accept-цикл;
- автоматическое определение TLS/HTTP по первому байту (0x16 → TLS, иначе HTTP с ответом 426);
- статистика: счётчики запросов по категориям кодов состояния, uptime, req/s;
- собственный платформенный шим (сокеты, строки, потоки, мьютексы, события) - модуль не зависит от внешних compat-заголовков.

### url

Самодостаточная HTTP/HTTPS-библиотека клиента, построенная на встроенном TLS-стеке:

- разбор абсолютных URL: http/https, явный порт, userinfo, фрагменты, IPv6-литералы;
- выполнение HTTP/1.1-запросов (GET, POST, HEAD и др.) с кастомными заголовками, телом, Content-Type, Range;
- чтение ответа: статус-строка, заголовки, тело по Content-Length, chunked transfer encoding или до EOF;
- обработка редиректов (301/302/303/307/308) с семантикой методов по RFC 7231 и ограничением числа переходов;
- сборка multipart/form-data тел (поля и файлы, генерация boundary, определение MIME по расширению);
- скачивание файлов на диск через `url_download_file()`: тела до 10 МБ читаются как обычно (в память) и записываются в файл, большие (или неизвестного размера / chunked) стримятся на диск частями — лимиты I/O применяются к каждой полученной части (своё свежее окно таймаута на каждое чтение), а не ко всему соединению, поэтому длинная загрузка идёт до тех пор, пока данные приходят; докачка через Range/206 дописывается в существующий файл;
- хранилище куков: один общий список в памяти на все `UrlCtx` с опциональным сохранением в файл (`ctx->use_cook` / `ctx->cook_file`); сопоставление по правилам RFC 6265 (Domain/Path, Secure только по TLS, Max-Age/Expires), автоматическое сохранение `Set-Cookie` и отправка `Cookie` при GET;
- транспортный слой: DNS-резолвинг, подключение с таймаутом, TLS-рукопожатие (SNI, опция пропуска проверки сертификата), буферизованный ввод-вывод;
- коды ошибок, совместимые с конвенциями curl;
- опциональное подробное логирование через колбэк (отключается `URL_NO_LOG`).

## Основные используемые технологии

- **Язык**: чистый C/CPP, без внешних зависимостей (zlib - опционально).
- **Протоколы**: TLS 1.2, TLS 1.3, HTTP/1.1, HTTPS, WebSocket (RFC 6455), SSE, chunked transfer encoding.
- **Криптография**: AES-128-GCM, SHA-256, HMAC-SHA256, HKDF-SHA256, RSA-2048 (PKCS#1 v1.5, RSASSA-PSS), ECDH P-256 (secp256r1), X25519, X.509 (DER/PEM), SHA-1 (только для WebSocket-рукопожатия).
- **Сетевой уровень**: Winsock2 (Windows) / BSD-сокеты (POSIX), `select()` для таймаутов, `SO_RCVTIMEO`, `getaddrinfo` для DNS.
- **Потоки**: WinAPI-потоки (Windows) / pthreads (POSIX), пул рабочих потоков, критические секции / мьютексы, автосбрасываемые события.
- **Сжатие**: gzip через zlib (опционально).
- **Совместимость API**: OpenSSL (SSL_CTX/SSL) и curl (url_*).

## Примеры использования

Проекты использующие сетевой стек Crypery:

- https://github.com/crypery/mini-cert
- https://github.com/crypery/mini-acme
- https://github.com/crypery/mini-ftps


### tls

Проект использующий эту библиотеку:
- https://github.com/crypery/mini-tls

Генерация ключа, самоподписанного сертификата и проведение рукопожатия:

```c
#include "tls.h"

/* Генерация RSA-2048 ключа и самоподписанного сертификата */
RSAKey key;
tls_rsa_generate_key(&key);

uint8_t cert[TLS_RSA_MAX_CERT_SIZE];
int cert_len = sizeof(cert);
tls_generate_self_signed_cert(&key, cert, &cert_len);

/* Серверный контекст с автовыбором версии TLS */
TLSContext ctx;
tls_init_context_auto(&ctx, 1);
tls_set_rsa_key(&ctx, &key);
tls_set_certificate(&ctx, cert, cert_len);

/* Пошаговое рукопожатие: подаём входящие данные, получаем исходящие */
uint8_t in[TLS_RSA_MAX_BUFFER], out[TLS_RSA_MAX_BUFFER];
int in_len = 0, out_len = 0;
int ret = tls_handshake_step(&ctx, in, in_len, out, &out_len);
/*... отправка out и повторный вызов с новыми in до завершения... */

/* Шифрованная отправка и приём данных приложения */
uint8_t data[] = "hello";
ret = tls_send_application_data(&ctx, data, sizeof(data) - 1, out, &out_len);

uint8_t plain[TLS_RSA_MAX_BUFFER];
int plain_len = sizeof(plain);
ret = tls_receive_application_data(&ctx, in, in_len, plain, &plain_len);

/* Корректное закрытие соединения */
tls_close(&ctx, out, &out_len);
```

### ssl

OpenSSL-совместимый сервер:

```c
#include "ssl.h"

/* Контекст: загрузка сертификата и ключа из PEM */
SSL_CTX *ctx = SSL_CTX_new();
SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM);
SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM);
SSL_CTX_check_private_key(ctx);

/* Таймауты (мс) */
ssl_set_io_timeout(ctx, 5000);
ssl_set_handshake_timeout(ctx, 10000);

/* Соединение на принятом сокете */
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

Клиентская сторона аналогична: `SSL_connect()` вместо `SSL_accept()`.

### http

Проект использующий эту библиотеку:
- https://github.com/crypery/mini-https

Сервер с маршрутом API и раздачей статики:

```c
#include "http.h"

/* Обработчик маршрута */
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

    /* корневые каталоги по доменам; хосты вне списка отклоняются (400) */
    http_domain(http, "localhost", "www");
    http_domain(http, "127.0.0.1", "www");
    http_domain(http, "test.localhost", "test");

    /* маршруты привязаны к домену: зарегистрирован только для "localhost" */
    http_route(http, "localhost", "GET", "/api/info", handle_info);

    http_run(http, my_log_cb);   /* NULL - отключить логирование модуля */
    http_free(http);
    return 0;
}
```

Запросы к путям без зарегистрированных маршрутов автоматически обслуживаются раздачей статических файлов из корневого каталога домена запроса `Host` (см. `http_domain()`), а при отсутствии настроенных доменов - все хосты обслуживаются из встроенного корня по умолчанию `DEF_ROOT` (`www`). Маршруты регистрируются отдельно для каждого домена: `http_route(http, domain, method, path, handler)` действует только для этого домена, а при `domain = NULL` - для всех доменов. Статические файлы до 10 МБ читаются в память и отправляются одним ответом; большие файлы стримятся клиенту частями (лимиты I/O применяются к отправленным частям, а не ко всей передаче), причём каждое соединение держит свой `FILE*`, поэтому файл не блокируется и несколько клиентов могут скачивать его одновременно.

### url

Проект использующий эту библиотеку:
- https://github.com/crypery/mini-curl

Выполнение HTTPS-запроса:

```c
#include "url.h"

UrlCtx *ctx = url_init();
ctx->verbose = 1;                          /* подробный вывод в консоль */
ctx->follow_redirects = 1;                 /* следовать редиректам */

url_set_header(ctx, "X-Api-Key", "123");   /* кастомный заголовок */
url_set_data(ctx, "a=1&b=2", 7);           /* тело POST */
url_set_content_type(ctx, "application/x-www-form-urlencoded");

char *data = url_run(ctx, "https://example.com", "POST", NULL);
if (data) {
    printf("status: %d\n", url_status(ctx));
    printf("%s", data);
    free(data);                            /* буфер выделяется url_run() */
} else {
    printf("error: %d\n", ctx->last_error);
}
url_free(ctx);
```

Скачивание большого файла на диск (не в консоль):

```c
#include "url.h"

UrlCtx *ctx = url_init();
ctx->follow_redirects = 1;                 /* CDN обычно редиректят */

size_t saved = 0;
if (url_download_file(ctx, "https://example.com/model.bin",
                      "model.bin", NULL, &saved) == 0) {
    /* Тела до 10 МБ идут классическим путём (в память), большие (или
     * неизвестного размера / chunked) стримятся в "model.bin" частями.
     * При установленном Range (url_set_range) и ответе 206 полученная
     * часть дописывается в существующий файл (докачка). */
    printf("saved %zu bytes (status %d)\n", saved, url_status(ctx));
} else {
    printf("error: %d\n", ctx->last_error); /* код URL_ERR_* */
}
url_free(ctx);
```

Куки (общее хранилище):

```c
#include "url.h"

UrlCtx *ctx = url_init();

/* Включаем хранилище куков. Куки хранятся в одном общем списке в памяти и,
 * так как задан cook_file, при первом url_run() загружаются из "cookies.txt"
 * (если файл существует), а при каждом Set-Cookie снова записываются в него -
 * при следующем запуске приложения куки подхватываются из файла.
 * ctx->cook_file = NULL означает хранение только в памяти. */
ctx->use_cook  = true;
ctx->cook_file = "cookies.txt";

char *data = url_run(ctx, "https://example.com/login", "GET", NULL);
if (data) {
    /* Сервер ответил "Set-Cookie: sid=abc; Path=/" - кука сохранена
     * в общем списке и записана в cookies.txt. */
    free(data);
}

/* Следующий запрос автоматически уйдёт с заголовком "Cookie: sid=abc" (GET) */
data = url_run(ctx, "https://example.com/profile", "GET", NULL);
if (data) {
    printf("%s", data);
    free(data);
}
url_free(ctx);
```

Хранилище — единый список на все `UrlCtx`; сопоставление по правилам RFC 6265 (атрибуты Domain/Path, Secure только по TLS, Max-Age/Expires). Для прямого доступа к списку доступны `url_cookie_header_for()`, `url_cookie_set_from_url()`, `url_cookie_load()` и `url_cookie_save()`.

## License

GNU AGPL v3 (Affero GPL)