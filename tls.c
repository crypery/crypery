/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * tls.c - pure C TLS 1.2/1.3 and RSA cryptography library.
 *
 * All algorithms are implemented from scratch with no external
 * dependencies: AES-128-GCM, SHA-256, HMAC-SHA256, RSA-2048
 * (PKCS#1 v1.5 and RSASSA-PSS), ECDH X25519 and P-256,
 * HKDF-SHA256, generation of self-signed X.509 (DER/PEM)
 * certificates. Works on Windows (MinGW, ws2_32) and Unix-like systems.
 */

#include "tls.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifndef NULL
#define NULL ((void*)0)
#endif

/* The TLS library runs with several worker threads doing handshakes at the
 * same time (server thread pool, browser clients). All randomness flows
 * through tls_random()/prng_next(), which mutate a shared xorshift128 state;
 * without a lock concurrent handshakes race on it and produce corrupted or
 * duplicated ephemeral keys/random values, making handshakes fail under load.
 * Serialize access on a per-call basis. */
#ifdef _WIN32
#include <windows.h>
static INIT_ONCE g_prng_once = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_prng_cs;

static BOOL CALLBACK prng_init_once(PINIT_ONCE once, PVOID p, PVOID *ctx) {
    (void)once; (void)p; (void)ctx;
    InitializeCriticalSection(&g_prng_cs);
    return TRUE;
}
static void prng_lock(void) {
    InitOnceExecuteOnce(&g_prng_once, prng_init_once, NULL, NULL);
    EnterCriticalSection(&g_prng_cs);
}
static void prng_unlock(void) {
    LeaveCriticalSection(&g_prng_cs);
}
#else
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
static pthread_mutex_t g_prng_mtx = PTHREAD_MUTEX_INITIALIZER;
static void prng_lock(void) { pthread_mutex_lock(&g_prng_mtx); }
static void prng_unlock(void) { pthread_mutex_unlock(&g_prng_mtx); }
#endif


static uint32_t prng_state[4] = {0};


// Seed the software PRNG (xorshift128)
static void prng_seed(void) {
    prng_state[0] = (uint32_t)time(NULL);
    prng_state[1] = (uint32_t)(uintptr_t)&prng_state;
    prng_state[2] = (uint32_t)clock();
    prng_state[3] = prng_state[0] ^ prng_state[1] ^ 0xDEADBEEF;
    for (int i = 0; i < 100; i++) {
        uint32_t t = prng_state[3];
        t ^= t << 13;
        t ^= t >> 17;
        t ^= t << 5;
        prng_state[3] = prng_state[2];
        prng_state[2] = prng_state[1];
        prng_state[1] = prng_state[0];
        prng_state[0] = t;
    }
}


// Next 32-bit pseudo-random number
static uint32_t prng_next(void) {
    uint32_t t = prng_state[3];
    t ^= t << 13;
    t ^= t >> 17;
    t ^= t << 5;
    prng_state[3] = prng_state[2];
    prng_state[2] = prng_state[1];
    prng_state[1] = prng_state[0];
    prng_state[0] = t;
    return t;
}


// Fill a buffer with random bytes
static int tls_random(uint8_t *buf, int len) {
    prng_lock();
    if (prng_state[0] == 0 && prng_state[1] == 0 && prng_state[2] == 0 && prng_state[3] == 0)
        prng_seed();
    int pos = 0;
    while (pos + 4 <= len) {
        uint32_t r = prng_next();
        buf[pos++] = (r >> 24) & 0xFF;
        buf[pos++] = (r >> 16) & 0xFF;
        buf[pos++] = (r >> 8) & 0xFF;
        buf[pos++] = r & 0xFF;
    }
    if (pos < len) {
        uint32_t r = prng_next();
        while (pos < len) { buf[pos++] = r & 0xFF; r >>= 8; }
    }
    prng_unlock();
    return 0;
}


// Write a 16-bit value in big-endian
static void w16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xFF; }

// Write a 32-bit value in big-endian
static void w32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

// Write a 64-bit value in big-endian
static void w64(uint8_t *p, uint64_t v) { for (int i = 7; i >= 0; i--) { p[i] = v & 0xFF; v >>= 8; } }

// Read a 16-bit value (big-endian)
static uint16_t r16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }


static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rcon[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };


// Initialize the AES-128 key and round keys
int aes_init_key(AESKey *key, const uint8_t *data) {
    uint32_t temp;
    key->rounds = 10;
    for (int i = 0; i < 4; i++)
        key->rk[i] = ((uint32_t)data[4*i] << 24) | ((uint32_t)data[4*i+1] << 16) |
                     ((uint32_t)data[4*i+2] << 8) | data[4*i+3];
    for (int i = 4; i < 44; i++) {
        temp = key->rk[i-1];
        if (i % 4 == 0) {
            uint32_t t = temp;
            temp = ((uint32_t)sbox[(t >> 16) & 0xFF] << 24) |
                   ((uint32_t)sbox[(t >> 8) & 0xFF] << 16) |
                   ((uint32_t)sbox[t & 0xFF] << 8) |
                   ((uint32_t)sbox[(t >> 24) & 0xFF]);
            temp ^= ((uint32_t)rcon[i/4] << 24);
        }
        key->rk[i] = key->rk[i-4] ^ temp;
    }
    memcpy(key->key, data, 16);
    return 0;
}


// Encrypt a single 16-byte AES-128 block
int aes_encrypt_block(const AESKey *key, const uint8_t *in, uint8_t *out) {
    uint8_t s[16], tmp;
    memcpy(s, in, 16);
    for (int i = 0; i < 4; i++) { s[i*4] ^= key->rk[i] >> 24; s[i*4+1] ^= key->rk[i] >> 16; s[i*4+2] ^= key->rk[i] >> 8; s[i*4+3] ^= key->rk[i]; }
    for (int r = 1; r < 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
        tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
        tmp = s[2]; s[2] = s[10]; s[10] = tmp; tmp = s[6]; s[6] = s[14]; s[14] = tmp;
        tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
        for (int c = 0; c < 4; c++) {
            int i = c*4;
            uint8_t a = s[i], b = s[i+1], cc = s[i+2], d = s[i+3];
            uint8_t x = a ^ b ^ cc ^ d;
            uint8_t xtime_ab = (uint8_t)((a ^ b) << 1) ^ (((a ^ b) >> 7) & 1) * 0x1b;
            uint8_t xtime_bc = (uint8_t)((b ^ cc) << 1) ^ (((b ^ cc) >> 7) & 1) * 0x1b;
            uint8_t xtime_cd = (uint8_t)((cc ^ d) << 1) ^ (((cc ^ d) >> 7) & 1) * 0x1b;
            uint8_t xtime_da = (uint8_t)((d ^ a) << 1) ^ (((d ^ a) >> 7) & 1) * 0x1b;
            s[i]   ^= x ^ xtime_ab;
            s[i+1] ^= x ^ xtime_bc;
            s[i+2] ^= x ^ xtime_cd;
            s[i+3] ^= x ^ xtime_da;
        }
        for (int i = 0; i < 4; i++) { s[i*4] ^= key->rk[r*4+i] >> 24; s[i*4+1] ^= key->rk[r*4+i] >> 16; s[i*4+2] ^= key->rk[r*4+i] >> 8; s[i*4+3] ^= key->rk[r*4+i]; }
    }
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
    tmp = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
    tmp = s[2]; s[2] = s[10]; s[10] = tmp; tmp = s[6]; s[6] = s[14]; s[14] = tmp;
    tmp = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;
    for (int i = 0; i < 4; i++) { s[i*4] ^= key->rk[40+i] >> 24; s[i*4+1] ^= key->rk[40+i] >> 16; s[i*4+2] ^= key->rk[40+i] >> 8; s[i*4+3] ^= key->rk[40+i]; }
    memcpy(out, s, 16);
    return 0;
}


// Multiplication in GF(2^128) for GCM
static void gf_mult(const uint8_t *X, const uint8_t *Y, uint8_t *Z) {
    uint8_t V[16];
    memcpy(V, Y, 16);
    uint8_t Xc[16];
    memcpy(Xc, X, 16);
    memset(Z, 0, 16);
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            if (Xc[i] & (1 << (7 - j))) { for (int k = 0; k < 16; k++) Z[k] ^= V[k]; }
            uint8_t carry = V[15] & 1;
            for (int k = 15; k > 0; k--) V[k] = (V[k] >> 1) | (V[k-1] << 7);
            V[0] >>= 1;
            if (carry) V[0] ^= 0xe1;
        }
    }
}


// Multiply by the GCM constant H
static void gcm_mult_h(GCMState *gcm, uint8_t *X) { gf_mult(gcm->H, X, X); }


// Initialize an AES-GCM context
int gcm_init(GCMState *gcm, const uint8_t *key, int key_len) {
    uint8_t B[16];
    memset(gcm, 0, sizeof(GCMState));
    if (aes_init_key(&gcm->K, key) != 0) return -1;
    gcm->cipher = 1;
    memset(B, 0, 16);
    aes_encrypt_block(&gcm->K, B, gcm->H);
    gcm->mode = 0;
    return 0;
}


// Reset the GCM state for a new message
int gcm_reset(GCMState *gcm) {
    memset(gcm->buf, 0, 16); memset(gcm->X, 0, 16);
    gcm->mode = 0; gcm->ivmode = 0; gcm->buflen = 0; gcm->totlen = 0; gcm->pttotlen = 0;
    return 0;
}


// Set the GCM initialization vector
int gcm_add_iv(GCMState *gcm, const uint8_t *IV, int IVlen) {
    if (gcm->mode != 0) return -1;
    for (int i = 0; i < IVlen; i++) {
        gcm->buf[gcm->buflen++] = IV[i];
        if (gcm->buflen == 16) { for (int y = 0; y < 16; y++) gcm->X[y] ^= gcm->buf[y]; gcm_mult_h(gcm, gcm->X); gcm->buflen = 0; gcm->totlen += 128; }
    }
    return 0;
}


// Add extra authenticated data (AAD)
int gcm_add_aad(GCMState *gcm, const uint8_t *adata, int adatalen) {
    if (gcm->mode == 0) {
        if (gcm->ivmode || gcm->buflen != 12) {
            for (int x = 0; x < gcm->buflen; x++) gcm->X[x] ^= gcm->buf[x];
            if (gcm->buflen) { gcm->totlen += gcm->buflen * 8; gcm_mult_h(gcm, gcm->X); }
            memset(gcm->buf, 0, 8);
            uint64_t tl = gcm->totlen;
            for (int i = 7; i >= 0; i--) { gcm->buf[8+i] = tl & 0xFF; tl >>= 8; }
            for (int x = 0; x < 16; x++) gcm->X[x] ^= gcm->buf[x];
            gcm_mult_h(gcm, gcm->X);
            memcpy(gcm->Y, gcm->X, 16);
            memset(gcm->X, 0, 16);
        } else {
            memcpy(gcm->Y, gcm->buf, 12); gcm->Y[12] = 0; gcm->Y[13] = 0; gcm->Y[14] = 0; gcm->Y[15] = 1;
        }
        memcpy(gcm->Y_0, gcm->Y, 16);
        memset(gcm->buf, 0, 16); gcm->buflen = 0; gcm->totlen = 0; gcm->mode = 1;
    }
    if (gcm->mode != 1) return -1;
    for (int x = 0; x < adatalen; x++) {
        gcm->X[gcm->buflen++] ^= adata[x];
        if (gcm->buflen == 16) { gcm_mult_h(gcm, gcm->X); gcm->buflen = 0; gcm->totlen += 128; }
    }
    return 0;
}


// Encrypt or decrypt data in GCM mode
int gcm_process(GCMState *gcm, uint8_t *pt, uint8_t *ct, int len, int direction) {
    if (gcm->mode == 1) {
        if (gcm->buflen) { gcm->totlen += gcm->buflen * 8; gcm_mult_h(gcm, gcm->X); }
        for (int y = 15; y >= 12; y--) if (++gcm->Y[y] & 255) break;
        aes_encrypt_block(&gcm->K, gcm->Y, gcm->buf);
        gcm->buflen = 0; gcm->mode = 2;
    }
    if (gcm->mode != 2) return -1;
    for (int x = 0; x < len; x++) {
        if (gcm->buflen == 16) {
            gcm->pttotlen += 128; gcm_mult_h(gcm, gcm->X);
            for (int y = 15; y >= 12; y--) if (++gcm->Y[y] & 255) break;
            aes_encrypt_block(&gcm->K, gcm->Y, gcm->buf);
            gcm->buflen = 0;
        }
        uint8_t b;
        if (direction == 0) { ct[x] = pt[x] ^ gcm->buf[gcm->buflen]; b = ct[x]; }
        else { b = ct[x]; pt[x] = ct[x] ^ gcm->buf[gcm->buflen]; }
        gcm->X[gcm->buflen++] ^= b;
    }
    return 0;
}


// Finish GCM and compute the authentication tag
int gcm_done(GCMState *gcm, uint8_t *tag, int *taglen) {
    if (gcm->mode != 2) return -1;
    if (gcm->buflen) { gcm->pttotlen += gcm->buflen * 8; gcm_mult_h(gcm, gcm->X); }
    uint8_t buf[16];
    uint64_t tl = gcm->totlen, ptl = gcm->pttotlen;
    for (int i = 7; i >= 0; i--) { buf[i] = tl & 0xFF; tl >>= 8; }
    for (int i = 7; i >= 0; i--) { buf[8+i] = ptl & 0xFF; ptl >>= 8; }
    for (int x = 0; x < 16; x++) gcm->X[x] ^= buf[x];
    gcm_mult_h(gcm, gcm->X);
    aes_encrypt_block(&gcm->K, gcm->Y_0, buf);
    int tl_out = *taglen < 16 ? *taglen : 16;
    for (int x = 0; x < tl_out; x++) tag[x] = buf[x] ^ gcm->X[x];
    *taglen = tl_out;
    return 0;
}


static const uint32_t k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define RR(x,n) ((x)>>(n)|((x)<<(32-(n))))
#define S0(x) (RR(x,2)^RR(x,13)^RR(x,22))
#define S1(x) (RR(x,6)^RR(x,11)^RR(x,25))
#define s0(x) (RR(x,7)^RR(x,18)^((x)>>3))
#define s1(x) (RR(x,17)^RR(x,19)^((x)>>10))


// Compress one 64-byte SHA-256 block
static void sha256_compress(SHA256State *md, const uint8_t *buf) {
    uint32_t W[64], a, b, c, d, e, f, g, h, t1, t2;
    for (int i = 0; i < 16; i++) W[i] = ((uint32_t)buf[i*4] << 24) | ((uint32_t)buf[i*4+1] << 16) | ((uint32_t)buf[i*4+2] << 8) | buf[i*4+3];
    for (int i = 16; i < 64; i++) W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];
    a = md->state[0]; b = md->state[1]; c = md->state[2]; d = md->state[3];
    e = md->state[4]; f = md->state[5]; g = md->state[6]; h = md->state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + S1(e) + ((e&f)^((~e)&g)) + k256[i] + W[i];
        t2 = S0(a) + ((a&b)^(a&c)^(b&c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    md->state[0] += a; md->state[1] += b; md->state[2] += c; md->state[3] += d;
    md->state[4] += e; md->state[5] += f; md->state[6] += g; md->state[7] += h;
}


// Initialize a SHA-256 context
int sha256_init(SHA256State *md) {
    md->curlen = 0; md->length = 0;
    md->state[0] = 0x6A09E667UL; md->state[1] = 0xBB67AE85UL; md->state[2] = 0x3C6EF372UL; md->state[3] = 0xA54FF53AUL;
    md->state[4] = 0x510E527FUL; md->state[5] = 0x9B05688CUL; md->state[6] = 0x1F83D9ABUL; md->state[7] = 0x5BE0CD19UL;
    return 0;
}


// Process input data for SHA-256
int sha256_process(SHA256State *md, const uint8_t *in, int inlen) {
    while (inlen > 0) {
        if (md->curlen == 0 && inlen >= 64) {
            sha256_compress(md, in); md->length += 512; in += 64; inlen -= 64;
        } else {
            int n = inlen < (64 - md->curlen) ? inlen : (64 - md->curlen);
            memcpy(md->buf + md->curlen, in, n); md->curlen += n; in += n; inlen -= n;
            if (md->curlen == 64) { sha256_compress(md, md->buf); md->length += 512; md->curlen = 0; }
        }
    }
    return 0;
}


// Finish SHA-256 and output the digest
int sha256_done(SHA256State *md, uint8_t *out) {
    md->length += md->curlen * 8;
    md->buf[md->curlen++] = 0x80;
    if (md->curlen > 56) { while (md->curlen < 64) md->buf[md->curlen++] = 0; sha256_compress(md, md->buf); md->curlen = 0; }
    while (md->curlen < 56) md->buf[md->curlen++] = 0;
    for (int i = 7; i >= 0; i--) { md->buf[56 + (7-i)] = (md->length >> (i*8)) & 0xFF; }
    sha256_compress(md, md->buf);
    for (int i = 0; i < 8; i++) { out[i*4] = (md->state[i] >> 24) & 0xFF; out[i*4+1] = (md->state[i] >> 16) & 0xFF; out[i*4+2] = (md->state[i] >> 8) & 0xFF; out[i*4+3] = md->state[i] & 0xFF; }
    return 0;
}


// Initialize HMAC-SHA256 with a key
int hmac_sha256_init(HMACState *hmac, const uint8_t *key, int keylen) {
    uint8_t k_pad[64];
    memset(k_pad, 0, 64);
    if (keylen > 64) {
        sha256_init(&hmac->hashstate); sha256_process(&hmac->hashstate, key, keylen); sha256_done(&hmac->hashstate, k_pad);
    } else memcpy(k_pad, key, keylen);
    memcpy(hmac->key, k_pad, 64);
    for (int i = 0; i < 64; i++) k_pad[i] ^= 0x36;
    sha256_init(&hmac->sha); sha256_process(&hmac->sha, k_pad, 64);
    return 0;
}


// Process data for HMAC-SHA256
int hmac_sha256_process(HMACState *hmac, const uint8_t *in, int inlen) {
    return sha256_process(&hmac->sha, in, inlen);
}


// Finish HMAC-SHA256 and output the MAC
int hmac_sha256_done(HMACState *hmac, uint8_t *out, int *outlen) {
    uint8_t isha[32], buf[64];
    sha256_done(&hmac->sha, isha);
    for (int i = 0; i < 64; i++) buf[i] = hmac->key[i] ^ 0x5C;
    sha256_init(&hmac->hashstate); sha256_process(&hmac->hashstate, buf, 64);
    sha256_process(&hmac->hashstate, isha, 32); sha256_done(&hmac->hashstate, buf);
    int len = *outlen < 32 ? *outlen : 32;
    memcpy(out, buf, len); *outlen = len;
    return 0;
}


// Check whether a big number is zero
static int bn_is_zero(const uint8_t *a, int len) { for (int i = 0; i < len; i++) if (a[i]) return 0; return 1; }

// Compare big numbers
static int bn_cmp(const uint8_t *a, const uint8_t *b, int len) { for (int i = 0; i < len; i++) { if (a[i] > b[i]) return 1; if (a[i] < b[i]) return -1; } return 0; }


// Add big numbers
static void bn_add(uint8_t *r, const uint8_t *a, const uint8_t *b, int len) {
    uint16_t carry = 0;
    for (int i = len - 1; i >= 0; i--) { carry += a[i] + b[i]; r[i] = carry & 0xFF; carry >>= 8; }
}


// Subtract big numbers
static void bn_sub(uint8_t *r, const uint8_t *a, const uint8_t *b, int len) {
    uint16_t borrow = 0;
    for (int i = len - 1; i >= 0; i--) { int diff = a[i] - b[i] - borrow; if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0; r[i] = diff & 0xFF; }
}


// Add big numbers modulo n
static void bn_add_mod(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, int len) {
    uint16_t carry = 0;
    for (int i = len - 1; i >= 0; i--) { carry += a[i] + b[i]; r[i] = carry & 0xFF; carry >>= 8; }
    if (carry) {
        uint16_t c = 1;
        for (int i = len - 1; i >= 0; i--) { c += (uint16_t)(uint8_t)(~m[i]) + r[i]; r[i] = c & 0xFF; c >>= 8; }
    } else if (bn_cmp(r, m, len) >= 0) {
        uint16_t borrow = 0;
        for (int i = len - 1; i >= 0; i--) { int diff = r[i] - m[i] - borrow; if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0; r[i] = diff & 0xFF; }
    }
}


// Subtract big numbers modulo n
static void bn_sub_mod(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, int len) {
    int borrow = 0;
    for (int i = len - 1; i >= 0; i--) { int diff = a[i] - b[i] - borrow; if (diff < 0) { diff += 256; borrow = 1; } else borrow = 0; r[i] = diff & 0xFF; }
    if (borrow) {
        uint16_t carry = 0;
        for (int i = len - 1; i >= 0; i--) { carry += (uint16_t)r[i] + m[i]; r[i] = carry & 0xFF; carry >>= 8; }
    }
}


// Multiply big numbers without modular reduction
static void bn_mul_raw(uint8_t *r, const uint8_t *a, const uint8_t *b, int len) {
    memset(r, 0, len * 2);
    for (int i = len - 1; i >= 0; i--) {
        uint16_t carry = 0;
        for (int j = len - 1; j >= 0; j--) { carry += (uint16_t)a[i] * b[j] + r[i + j + 1]; r[i + j + 1] = carry & 0xFF; carry >>= 8; }
        r[i] += carry & 0xFF;
    }
}


// Reduce a big number modulo n
static void bn_mod(uint8_t *r, const uint8_t *a, int alen, const uint8_t *m, int mlen) {
    uint8_t c[32], hi[32], lo[32], prod[64], sum[64];
    uint16_t carry = 1;
    for (int i = mlen - 1; i >= 0; i--) { carry += (uint16_t)(uint8_t)(~m[i]); c[i] = carry & 0xFF; carry >>= 8; }
    if (alen == mlen) { memset(hi, 0, mlen); memcpy(lo, a, mlen); }
    else { memcpy(hi, a, mlen); memcpy(lo, a + mlen, mlen); }
    for (int iter = 0; iter < 64 && !bn_is_zero(hi, mlen); iter++) {
        bn_mul_raw(prod, hi, c, mlen);
        uint16_t cc = 0;
        for (int i = mlen * 2 - 1; i >= mlen; i--) { uint16_t v = prod[i] + lo[i - mlen] + cc; sum[i] = v & 0xFF; cc = v >> 8; }
        for (int i = mlen - 1; i >= 0; i--) { uint16_t v = prod[i] + cc; sum[i] = v & 0xFF; cc = v >> 8; }
        memcpy(hi, sum, mlen); memcpy(lo, sum + mlen, mlen);
    }
    while (bn_cmp(lo, m, mlen) >= 0) bn_sub(lo, lo, m, mlen);
    memcpy(r, lo, mlen);
}


// Multiply big numbers modulo n
static void bn_mul_mod(uint8_t *r, const uint8_t *a, const uint8_t *b, const uint8_t *m, int len) {
    uint8_t t[64];
    bn_mul_raw(t, a, b, len);
    bn_mod(r, t, len * 2, m, len);
}


// Square a big number modulo n
static void bn_sqr_mod(uint8_t *r, const uint8_t *a, const uint8_t *m, int len) { bn_mul_mod(r, a, a, m, len); }


// Modular inverse of a big number (Fermat)
static void bn_mod_inv(uint8_t *r, const uint8_t *a, const uint8_t *m, int len) {
    uint8_t result[32], base[32], exp[32];
    memcpy(base, a, len); memcpy(exp, m, len);
    int borrow = 2;
    for (int i = len - 1; i >= 0 && borrow > 0; i--) { int diff = exp[i] - borrow; if (diff < 0) { exp[i] = diff + 256; borrow = 1; } else { exp[i] = diff; borrow = 0; } }
    memset(result, 0, 32); result[len - 1] = 1;
    for (int i = 0; i < len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            uint8_t tmp[32];
            bn_sqr_mod(tmp, result, m, len);
            if ((exp[i] >> bit) & 1) bn_mul_mod(result, tmp, base, m, len);
            else memcpy(result, tmp, len);
        }
    }
    memcpy(r, result, len);
}

static const uint8_t P256_P[32] = { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
static const uint8_t P256_N[32] = { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 };
static const uint8_t P256_GX[32] = { 0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96 };
static const uint8_t P256_GY[32] = { 0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5 };

typedef struct { uint8_t x[32]; uint8_t y[32]; int infinity; } ECPoint;


// Double a point on the P-256 curve
static void ec_double(ECPoint *R, const ECPoint *P) {
    if (P->infinity) { R->infinity = 1; return; }
    ECPoint PP;
    if (R == P) { memcpy(&PP, P, sizeof(ECPoint)); P = &PP; }
    static const uint8_t P256_THREE[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3 };
    uint8_t lam[32], num[32], den[32], tmp[32], tmp2[32];
    bn_sqr_mod(tmp, P->x, P256_P, 32);
    bn_add_mod(num, tmp, tmp, P256_P, 32);
    bn_add_mod(num, num, tmp, P256_P, 32);
    bn_sub_mod(num, num, P256_THREE, P256_P, 32);
    bn_add_mod(den, P->y, P->y, P256_P, 32);
    bn_mod_inv(tmp, den, P256_P, 32);
    bn_mul_mod(lam, num, tmp, P256_P, 32);
    bn_sqr_mod(tmp, lam, P256_P, 32);
    bn_sub_mod(R->x, tmp, P->x, P256_P, 32);
    bn_sub_mod(R->x, R->x, P->x, P256_P, 32);
    bn_sub_mod(tmp2, P->x, R->x, P256_P, 32);
    bn_mul_mod(tmp, lam, tmp2, P256_P, 32);
    bn_sub_mod(R->y, tmp, P->y, P256_P, 32);
    R->infinity = 0;
}


// Add two points on the P-256 curve
static void ec_add(ECPoint *R, const ECPoint *P, const ECPoint *Q) {
    if (P->infinity) { memcpy(R, Q, sizeof(ECPoint)); return; }
    if (Q->infinity) { memcpy(R, P, sizeof(ECPoint)); return; }
    ECPoint PP, QQ;
    if (R == P) { memcpy(&PP, P, sizeof(ECPoint)); P = &PP; }
    if (R == Q) { memcpy(&QQ, Q, sizeof(ECPoint)); Q = &QQ; }
    if (memcmp(P->x, Q->x, 32) == 0) {
        uint8_t neg_y[32];
        bn_sub(neg_y, P256_P, P->y, 32);
        if (memcmp(neg_y, Q->y, 32) == 0) { R->infinity = 1; return; }
        if (memcmp(P->y, Q->y, 32) == 0) { ec_double(R, P); return; }
    }
    uint8_t lam[32], num[32], den[32], tmp[32], tmp2[32];
    bn_sub_mod(num, Q->y, P->y, P256_P, 32);
    bn_sub_mod(den, Q->x, P->x, P256_P, 32);
    bn_mod_inv(tmp, den, P256_P, 32);
    bn_mul_mod(lam, num, tmp, P256_P, 32);
    bn_sqr_mod(tmp, lam, P256_P, 32);
    bn_sub_mod(R->x, tmp, P->x, P256_P, 32);
    bn_sub_mod(R->x, R->x, Q->x, P256_P, 32);
    bn_sub_mod(tmp2, P->x, R->x, P256_P, 32);
    bn_mul_mod(tmp, lam, tmp2, P256_P, 32);
    bn_sub_mod(R->y, tmp, P->y, P256_P, 32);
    R->infinity = 0;
}


// Scalar multiplication of a point on the P-256 curve
static void ec_mul(ECPoint *R, const uint8_t *k, const ECPoint *P) {
    R->infinity = 1;
    for (int i = 0; i < 32; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if (!R->infinity) ec_double(R, R);
            if ((k[i] >> bit) & 1) {
                if (R->infinity) { memcpy(R->x, P->x, 32); memcpy(R->y, P->y, 32); R->infinity = 0; }
                else ec_add(R, R, P);
            }
        }
    }
}


// Verify ECDH consistency between two key pairs
int tls_test_ecdh_consistency(void) {
    ECKey a, b;

// Generate a P-256 (ECDH) key pair
    tls_generate_p256_key(&a);
    tls_generate_p256_key(&b);
    ECPoint A, B, S1, S2;
    memcpy(A.x, a.x, 32); memcpy(A.y, a.y, 32); A.infinity = 0;
    memcpy(B.x, b.x, 32); memcpy(B.y, b.y, 32); B.infinity = 0;
    ec_mul(&S1, a.k, &B);
    ec_mul(&S2, b.k, &A);
    return (memcmp(S1.x, S2.x, 32) == 0 && memcmp(S1.y, S2.y, 32) == 0) ? 0 : -1;
}

int tls_generate_p256_key(ECKey *key) {
    uint8_t k[32];
    ECPoint G, pub;
    memcpy(G.x, P256_GX, 32); memcpy(G.y, P256_GY, 32); G.infinity = 0;
    do { tls_random(k, 32); } while (bn_is_zero(k, 32) || bn_cmp(k, P256_N, 32) >= 0);
    ec_mul(&pub, k, &G);
    memcpy(key->k, k, 32); memcpy(key->x, pub.x, 32); memcpy(key->y, pub.y, 32);
    key->is_private = 1; key->curve = TLS_RSA_CURVE_SECP256R1;
    return 0;
}


typedef int64_t GF[16];
static const GF GF_121665 = {0xDB41, 1};
static const uint8_t X25519_BASE[32] = { 9 };


// Carry reduction of X25519 field limbs
static void x5_car(GF o) {
    for (int i = 0; i < 16; i++) {
        int64_t c;
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

// Constant-time bit selection (X25519)
static void x5_sel(GF p, GF q, int b) {
    int64_t t, c = ~(b - 1);
    for (int i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}

// Pack an X25519 field number into 32 bytes
static void x5_pack(uint8_t *o, const GF n) {
    GF m, t;
    int i, b;
    for (i = 0; i < 16; i++) t[i] = n[i];
    x5_car(t); x5_car(t); x5_car(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) { m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1); m[i-1] &= 0xffff; }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        x5_sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) { o[2*i] = (uint8_t)(t[i] & 0xff); o[2*i+1] = (uint8_t)(t[i] >> 8); }
}

// Unpack 32 bytes into X25519 field numbers
static void x5_unpack(GF o, const uint8_t *n) {
    for (int i = 0; i < 16; i++) o[i] = (int64_t)n[2*i] + ((int64_t)n[2*i+1] << 8);
    o[15] &= 0x7fff;
}

// Add X25519 field numbers
static void x5_add(GF o, const GF a, const GF b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }

// Subtract X25519 field numbers
static void x5_sub(GF o, const GF a, const GF b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

// Multiply X25519 field numbers
static void x5_mul(GF o, const GF a, const GF b) {
    int64_t t[31];
    for (int i = 0; i < 31; i++) t[i] = 0;
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 16; j++) t[i+j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i+16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    x5_car(o); x5_car(o);
}

// Square an X25519 field number
static void x5_sqr(GF o, const GF a) { x5_mul(o, a, a); }

// Inverse of an X25519 field number
static void x5_inv(GF o, const GF i) {
    GF c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) { x5_sqr(c, c); if (a != 2 && a != 4) x5_mul(c, c, i); }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}


// Scalar multiplication on Curve25519 (RFC 7748)
static void x25519_mul(uint8_t *out, const uint8_t *scalar, const uint8_t *point) {
    int64_t x[80];
    uint8_t z[32];
    GF a, b, c, d, e, f;
    for (int i = 0; i < 31; i++) z[i] = scalar[i];
    z[31] = (scalar[31] & 127) | 64;
    z[0]  &= 248;
    x5_unpack(x, point);
    for (int i = 0; i < 16; i++) { b[i] = x[i]; d[i] = a[i] = c[i] = 0; }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        x5_sel(a, b, r); x5_sel(c, d, r);
        x5_add(e, a, c); x5_sub(a, a, c); x5_add(c, b, d); x5_sub(b, b, d);
        x5_sqr(d, e); x5_sqr(f, a);
        x5_mul(a, c, a); x5_mul(c, b, e);
        x5_add(e, a, c); x5_sub(a, a, c); x5_sqr(b, a);
        x5_sub(c, d, f);
        x5_mul(a, c, GF_121665); x5_add(a, a, d); x5_mul(c, c, a);
        x5_mul(a, d, f); x5_mul(d, b, x); x5_sqr(b, e);
        x5_sel(a, b, r); x5_sel(c, d, r);
    }
    for (int i = 0; i < 16; i++) { x[i+16] = a[i]; x[i+32] = c[i]; x[i+48] = b[i]; x[i+64] = d[i]; }
    x5_inv(x + 32, x + 32);
    x5_mul(x + 16, x + 16, x + 32);
    x5_pack(out, x + 16);
}


// Generate an X25519 key pair
int tls_generate_x25519_key(X25519Key *key) {
    uint8_t t[32];
    do { tls_random(t, 32); } while (bn_is_zero(t, 32));
    memcpy(key->priv, t, 32);
    x25519_mul(key->pub, t, X25519_BASE);
    key->is_private = 1;
    return 0;
}


// Compute an X25519 shared secret
int tls_x25519_shared_secret(const uint8_t *priv, const uint8_t *peer_pub, uint8_t *shared) {
    x25519_mul(shared, priv, peer_pub);
    return 0;
}


#define MP_MAX_WORDS 160

typedef struct {
    uint32_t w[MP_MAX_WORDS];
    int len;
} MP;


// Strip leading zero words from a big number
static void mp_trim(MP *a) { while (a->len && a->w[a->len-1] == 0) a->len--; }

// Zero a big number
static void mp_zero(MP *a) { memset(a->w, 0, sizeof(a->w)); a->len = 0; }

// Copy a big number
static void mp_copy(MP *a, const MP *b) { memcpy(a->w, b->w, sizeof(b->w)); a->len = b->len; }

// Check whether a big number is zero
static int mp_iszero(const MP *a) { return a->len == 0; }


// Compare big numbers
static int mp_cmp(const MP *a, const MP *b) {
    if (a->len != b->len) return a->len < b->len ? -1 : 1;
    for (int i = a->len - 1; i >= 0; i--)
        if (a->w[i] != b->w[i]) return a->w[i] < b->w[i] ? -1 : 1;
    return 0;
}


// Add big numbers
static void mp_add(MP *r, const MP *a, const MP *b) {
    uint64_t carry = 0;
    int n = a->len > b->len ? a->len : b->len;
    for (int i = 0; i < n; i++) {
        uint64_t v = (uint64_t)(i < a->len ? a->w[i] : 0) + (i < b->len ? b->w[i] : 0) + carry;
        r->w[i] = (uint32_t)v;
        carry = v >> 32;
    }
    r->len = n;
    if (carry) { r->w[n] = (uint32_t)carry; r->len = n + 1; }
    mp_trim(r);
}


// Subtract big numbers
static void mp_sub(MP *r, const MP *a, const MP *b) {
    uint64_t borrow = 0;
    int n = a->len;
    for (int i = 0; i < n; i++) {
        int64_t av = a->w[i];
        int64_t bv = (i < b->len) ? b->w[i] : 0;
        int64_t diff = av - bv - borrow;
        if (diff < 0) { r->w[i] = (uint32_t)(diff + 4294967296LL); borrow = 1; }
        else { r->w[i] = (uint32_t)diff; borrow = 0; }
    }
    r->len = n;
    mp_trim(r);
}


// Shift a big number right by one bit
static void mp_shr1(MP *a) {
    for (int i = 0; i < a->len - 1; i++) a->w[i] = (a->w[i] >> 1) | (a->w[i+1] << 31);
    a->w[a->len - 1] >>= 1;
    mp_trim(a);
}


// Shift a big number left by a bit count
static void mp_shlbits(MP *r, const MP *a, int bits) {
    MP tmp;
    mp_copy(&tmp, a);
    mp_zero(r);
    if (mp_iszero(&tmp)) return;
    int words = bits >> 5, rem = bits & 31;
    for (int i = tmp.len - 1; i >= 0; i--) {
        uint64_t v = tmp.w[i];
        int pos = i + words;
        if (rem) {
            uint64_t lo = v << rem;
            uint64_t hi = v >> (32 - rem);
            if (pos < MP_MAX_WORDS) r->w[pos] |= (uint32_t)lo;
            if (hi && pos + 1 < MP_MAX_WORDS) r->w[pos + 1] |= (uint32_t)hi;
        } else {
            if (pos < MP_MAX_WORDS) r->w[pos] |= (uint32_t)v;
        }
    }
    r->len = 0;
    for (int i = MP_MAX_WORDS - 1; i >= 0; i--) if (r->w[i]) { r->len = i + 1; break; }
}


// Multiply big numbers
static void mp_mul(MP *r, const MP *a, const MP *b) {
    if (mp_iszero(a) || mp_iszero(b)) { mp_zero(r); return; }
    MP t;
    mp_zero(&t);
    for (int i = 0; i < a->len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->len; j++) {
            uint64_t z = (uint64_t)a->w[i] * b->w[j] + t.w[i + j] + carry;
            t.w[i + j] = (uint32_t)z;
            carry = z >> 32;
        }
        int pos = i + b->len;
        while (carry && pos < MP_MAX_WORDS) {
            uint64_t z = (uint64_t)t.w[pos] + carry;
            t.w[pos] = (uint32_t)z;
            carry = z >> 32;
            pos++;
        }
    }
    t.len = MP_MAX_WORDS;
    mp_trim(&t);
    mp_copy(r, &t);
}


// Bit length of a big number
static int mp_bitlen(const MP *a) {
    if (a->len == 0) return 0;
    uint32_t top = a->w[a->len - 1];
    int bits = 0;
    while (top) { top >>= 1; bits++; }
    return (a->len - 1) * 32 + bits;
}


// Test a bit of a big number
static int mp_testbit(const MP *a, int bit) {
    int w = bit >> 5, b = bit & 31;
    if (w >= a->len) return 0;
    return (a->w[w] >> b) & 1;
}


// Remainder of a big number modulo a power of two
static void mp_mod_shift(MP *r, const MP *u, const MP *v) {
    MP rem;
    mp_copy(&rem, u);
    int nb = mp_bitlen(&rem) - mp_bitlen(v);
    if (nb < 0) { mp_copy(r, &rem); return; }
    MP d;
    mp_zero(&d);
    mp_shlbits(&d, v, nb);
    for (int i = nb; i >= 0; i--) {
        if (mp_cmp(&rem, &d) >= 0) mp_sub(&rem, &rem, &d);
        mp_shr1(&d);
    }
    mp_copy(r, &rem);
}


// Compute the low word for Montgomery reduction
static uint32_t mp_mont_ninv0(uint32_t a) {
    uint32_t x = a;
    for (int i = 0; i < 5; i++) x = x * (2 - a * x);
    return (uint32_t)(0 - x);
}


// Montgomery multiplication with modular reduction
static void mp_mmul(MP *r, const MP *a, const MP *b, const MP *n, uint32_t ninv0) {
    int k = n->len;
    uint32_t T[2 * MP_MAX_WORDS + 2];
    memset(T, 0, sizeof(T));
    for (int i = 0; i < a->len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->len; j++) {
            uint64_t z = (uint64_t)a->w[i] * b->w[j] + T[i + j] + carry;
            T[i + j] = (uint32_t)z;
            carry = z >> 32;
        }
        int pos = i + b->len;
        while (carry) { uint64_t z = (uint64_t)T[pos] + carry; T[pos] = (uint32_t)z; carry = z >> 32; pos++; }
    }
    for (int i = 0; i < k; i++) {
        uint32_t m = T[i] * ninv0;
        uint64_t carry = 0;
        for (int j = 0; j < k; j++) {
            uint64_t z = (uint64_t)m * n->w[j] + T[i + j] + carry;
            T[i + j] = (uint32_t)z;
            carry = z >> 32;
        }
        int pos = i + k;
        while (carry) { uint64_t z = (uint64_t)T[pos] + carry; T[pos] = (uint32_t)z; carry = z >> 32; pos++; }
    }
    MP res;
    mp_zero(&res);
    res.len = k;
    for (int i = 0; i < k; i++) res.w[i] = T[i + k];
    if (T[2 * k]) { res.w[k] = T[2 * k]; res.len = k + 1; }
    mp_trim(&res);
    while (mp_cmp(&res, n) >= 0) mp_sub(&res, &res, n);
    mp_copy(r, &res);
}


// Modular exponentiation of a big number
static void mp_pow_mod(MP *r, const MP *base, const MP *exp, const MP *n) {
    if (mp_iszero(n)) return;
    int k = n->len;
    uint32_t ninv0 = mp_mont_ninv0(n->w[0]);
    MP R2, R2mod, one, mont_one, mont_base, acc, tmp;
    mp_zero(&R2); R2.len = 2 * k + 1; R2.w[2 * k] = 1;
    mp_mod_shift(&R2mod, &R2, n);
    mp_zero(&one); one.len = 1; one.w[0] = 1;
    mp_mmul(&mont_one, &one, &R2mod, n, ninv0);
    mp_mmul(&mont_base, base, &R2mod, n, ninv0);
    mp_copy(&acc, &mont_one);
    for (int i = mp_bitlen(exp) - 1; i >= 0; i--) {
        if (i != mp_bitlen(exp) - 1) { mp_mmul(&acc, &acc, &acc, n, ninv0); }
        if (mp_testbit(exp, i)) mp_mmul(&acc, &acc, &mont_base, n, ninv0);
    }
    mp_mmul(&tmp, &acc, &one, n, ninv0);
    mp_copy(r, &tmp);
}


// Remainder of a big number modulo a 32-bit value
static int mp_mod_u32(const MP *a, uint32_t m) {
    if (m == 0) return 0;
    uint64_t rem = 0;
    for (int i = a->len - 1; i >= 0; i--) rem = ((rem << 32) | a->w[i]) % m;
    return (int)rem;
}

typedef struct { MP v; int neg; } SGN;


// Subtract big numbers with sign
static void sgn_sub(SGN *out, const SGN *a, const SGN *b) {
    int c = mp_cmp(&a->v, &b->v);
    if (a->neg == b->neg) {
        if (c >= 0) { mp_sub(&out->v, &a->v, &b->v); out->neg = a->neg; }
        else { mp_sub(&out->v, &b->v, &a->v); out->neg = !a->neg; }
    } else {
        mp_add(&out->v, &a->v, &b->v);
        out->neg = a->neg;
    }
}


// Multiply big numbers with sign
static void sgn_mul(SGN *out, const SGN *a, const MP *q) {
    mp_mul(&out->v, &a->v, q);
    out->neg = a->neg;
}


// Modular inverse of a big number
static int mp_modinv(MP *r, const MP *a, const MP *m) {
    MP r0, r1, q, r2;
    SGN t0, t1, t2, mult;
    mp_copy(&r0, m);
    mp_copy(&r1, a);
    mp_zero(&t0.v); t0.neg = 0;
    mp_zero(&t1.v); t1.v.len = 1; t1.v.w[0] = 1; t1.neg = 0;
    while (!mp_iszero(&r1)) {

        mp_zero(&q);
        mp_copy(&r2, &r0);
        int nb = mp_bitlen(&r2) - mp_bitlen(&r1);
        if (nb < 0) nb = 0;
        MP d;
        mp_zero(&d);
        mp_shlbits(&d, &r1, nb);
        for (int i = nb; i >= 0; i--) {
            if (mp_cmp(&r2, &d) >= 0) {
                mp_sub(&r2, &r2, &d);
                if (i < MP_MAX_WORDS * 32) { q.w[i >> 5] |= 1u << (i & 31); if ((i >> 5) + 1 > q.len) q.len = (i >> 5) + 1; }
            }
            mp_shr1(&d);
        }

        sgn_mul(&mult, &t1, &q);
        sgn_sub(&t2, &t0, &mult);
        mp_copy(&r0, &r1);
        mp_copy(&r1, &r2);
        mp_copy(&t0.v, &t1.v); t0.neg = t1.neg;
        mp_copy(&t1.v, &t2.v); t1.neg = t2.neg;
    }
    MP one;
    mp_zero(&one); one.len = 1; one.w[0] = 1;
    if (mp_cmp(&r0, &one) != 0) return -1;

    if (t0.neg) { mp_sub(r, m, &t0.v); }
    else mp_mod_shift(r, &t0.v, m);
    return 0;
}

static const uint32_t small_primes[] = {
    2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
    101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,
    211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,
    331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,
    449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,
    587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,
    709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,
    853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,
    991,997,1009,1013,1019,1021,1031,1033,1039,1049,1051,1061,1063,1069,1087,1091,1093,
    1097,1103,1109,1117,1123,1129,1151,1153,1163,1171,1181,1187,1193,1201,1213,1217,1223
};


// Generate a random big number of a given bit length
static void mp_rand_bits(MP *r, int bits, int odd) {
    uint8_t buf[130];
    int bytes = (bits + 7) / 8;
    tls_random(buf, bytes);
    buf[0] |= 0x80;
    int rem = bits % 8;
    if (rem) buf[0] &= (uint8_t)(0xFF >> (8 - rem));
    if (odd) buf[bytes - 1] |= 1;
    mp_zero(r);
    for (int i = 0; i < bytes; i++) {
        int w = (bytes - 1 - i) >> 2;
        int b = (bytes - 1 - i) & 3;
        r->w[w] |= ((uint32_t)buf[i]) << (8 * b);
    }
    r->len = (bytes + 3) >> 2;
    mp_trim(r);
}


// Probable prime test (Miller-Rabin)
static int mp_is_probable_prime(const MP *a) {
    MP two_mp, p_mp, bv_mp;
    mp_zero(&two_mp); two_mp.len = 1; two_mp.w[0] = 2;
    if (a->len == 0) return 0;
    if (mp_mod_u32(a, 2) == 0) return (mp_cmp(a, &two_mp) == 0) ? 1 : 0;
    for (size_t i = 0; i < sizeof(small_primes) / sizeof(small_primes[0]); i++) {
        uint32_t p = small_primes[i];
        mp_zero(&p_mp); p_mp.len = 1; p_mp.w[0] = p;
        if (mp_mod_u32(a, p) == 0) return (mp_bitlen(a) == 32 && mp_cmp(a, &p_mp) == 0);
    }
    MP a1, d, two, x, base;
    mp_copy(&a1, a);
    MP one; mp_zero(&one); one.len = 1; one.w[0] = 1;
    mp_sub(&a1, &a1, &one);
    int s = 0;
    mp_copy(&d, &a1);
    while (mp_mod_u32(&d, 2) == 0) { s++; mp_shr1(&d); }
    mp_zero(&two); two.len = 1; two.w[0] = 2;
    static const uint32_t bases[] = { 2,3,5,7,11,13,17,19,23,29,31,37 };
    for (size_t bi = 0; bi < sizeof(bases) / sizeof(bases[0]); bi++) {
        uint32_t bv = bases[bi];
        mp_zero(&bv_mp); bv_mp.len = 1; bv_mp.w[0] = bv;
        if (mp_bitlen(a) <= 32 && mp_cmp(a, &bv_mp) <= 0) break;
        mp_zero(&base); base.len = 1; base.w[0] = bv;
        mp_pow_mod(&x, &base, &d, a);
        if (mp_cmp(&x, &one) == 0 || mp_cmp(&x, &a1) == 0) continue;
        int composite = 1;
        for (int i = 0; i < s - 1; i++) {
            mp_pow_mod(&x, &x, &two, a);
            if (mp_cmp(&x, &a1) == 0) { composite = 0; break; }
        }
        if (composite) return 0;
    }
    return 1;
}


// Convert bytes into a big number
static void mp_from_bytes(MP *a, const uint8_t *p, int len) {
    mp_zero(a);
    for (int i = 0; i < len; i++) {
        int w = (len - 1 - i) >> 2;
        int b = (len - 1 - i) & 3;
        a->w[w] |= ((uint32_t)p[i]) << (8 * b);
    }
    a->len = (len + 3) >> 2;
    mp_trim(a);
}


// Convert a big number into bytes
static void mp_to_bytes(const MP *a, uint8_t *out, int outlen) {
    memset(out, 0, outlen);
    int i = outlen;
    for (int w = 0; w < a->len && i > 0; w++) {
        uint32_t v = a->w[w];
        for (int b = 0; b < 4 && i > 0; b++) { out[--i] = v & 0xFF; v >>= 8; }
    }
}


// Generate an RSA key pair (2048 bits)
int tls_rsa_generate_key(RSAKey *key) {
    const uint32_t E = 65537;
    MP p, q, n, phi, e1, d, t1, t2;
    mp_zero(&e1); e1.len = 1; e1.w[0] = E;
    for (;;) {
        do { mp_rand_bits(&p, 1024, 1); } while (!mp_is_probable_prime(&p));
        do { mp_rand_bits(&q, 1024, 1); } while (!mp_is_probable_prime(&q) || mp_cmp(&q, &p) == 0);
        mp_mul(&n, &p, &q);
        if (mp_bitlen(&n) != 2048) continue;

        mp_zero(&t1); mp_copy(&t1, &p);
        MP one; mp_zero(&one); one.len = 1; one.w[0] = 1;
        mp_sub(&t1, &t1, &one);
        mp_copy(&t2, &q);
        mp_sub(&t2, &t2, &one);
        mp_mul(&phi, &t1, &t2);
        if (mp_modinv(&d, &e1, &phi) != 0) continue;
        break;
    }
    memset(key, 0, sizeof(RSAKey));
    key->n_len = TLS_RSA_MODULUS_BYTES;
    mp_to_bytes(&n, key->n, TLS_RSA_MODULUS_BYTES);
    key->e_len = 3;
    key->e[0] = 0x01; key->e[1] = 0x00; key->e[2] = 0x01;
    mp_to_bytes(&d, key->d, TLS_RSA_MODULUS_BYTES);
    key->is_private = 1;

    // CRT parameters: p, q, dmp1 = d mod (p-1), dmq1 = d mod (q-1), iqmp = q^-1 mod p
    MP one, p1, q1, dmp1, dmq1, iqmp;
    mp_zero(&one); one.len = 1; one.w[0] = 1;
    mp_sub(&p1, &p, &one);
    mp_sub(&q1, &q, &one);
    mp_mod_shift(&dmp1, &d, &p1);
    mp_mod_shift(&dmq1, &d, &q1);
    mp_modinv(&iqmp, &q, &p);
    mp_to_bytes(&p, key->p, TLS_RSA_MODULUS_BYTES / 2);
    mp_to_bytes(&q, key->q, TLS_RSA_MODULUS_BYTES / 2);
    mp_to_bytes(&dmp1, key->dmp1, TLS_RSA_MODULUS_BYTES / 2);
    mp_to_bytes(&dmq1, key->dmq1, TLS_RSA_MODULUS_BYTES / 2);
    mp_to_bytes(&iqmp, key->iqmp, TLS_RSA_MODULUS_BYTES / 2);
    return 0;
}


// RSA transform with the private key
static int rsa_private_op(const RSAKey *key, const uint8_t *in, int inlen, uint8_t *out, int outlen) {
    MP m, n, d, c;
    mp_from_bytes(&m, in, inlen);
    mp_from_bytes(&n, key->n, key->n_len);
    mp_from_bytes(&d, key->d, key->n_len);
    if (mp_cmp(&m, &n) >= 0) return -1;
    mp_pow_mod(&c, &m, &d, &n);
    mp_to_bytes(&c, out, outlen);
    return 0;
}


// RSA transform with the public key
static int rsa_public_op(const RSAKey *key, const uint8_t *in, int inlen, uint8_t *out, int outlen) {
    MP m, n, e, c;
    mp_from_bytes(&m, in, inlen);
    mp_from_bytes(&n, key->n, key->n_len);
    mp_from_bytes(&e, key->e, key->e_len);
    if (mp_cmp(&m, &n) >= 0) return -1;
    mp_pow_mod(&c, &m, &e, &n);
    mp_to_bytes(&c, out, outlen);
    return 0;
}


static const uint8_t RSA_DIGESTINFO_SHA256[19] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};


// Build the EM block for RSA PKCS#1 v1.5
static void build_pkcs1_em(uint8_t *em, int k, const uint8_t *hash) {
    em[0] = 0x00; em[1] = 0x01;
    for (int i = 2; i < k - TLS_RSA_DIGEST_INFO_SHA256 - 1; i++) em[i] = 0xFF;
    em[k - TLS_RSA_DIGEST_INFO_SHA256 - 1] = 0x00;
    memcpy(em + k - TLS_RSA_DIGEST_INFO_SHA256, RSA_DIGESTINFO_SHA256, sizeof(RSA_DIGESTINFO_SHA256));
    memcpy(em + k - TLS_RSA_DIGEST_INFO_SHA256 + sizeof(RSA_DIGESTINFO_SHA256), hash, 32);
}


// Sign a SHA-256 hash (RSA PKCS#1 v1.5)
int tls_rsa_sign(const RSAKey *key, const uint8_t *hash, uint8_t *sig, int *sig_len) {
    if (!key->is_private) return -1;
    int k = key->n_len;
    if (k < TLS_RSA_DIGEST_INFO_SHA256 + 3 || k > TLS_RSA_MODULUS_BYTES) return -1;
    uint8_t em[TLS_RSA_MODULUS_BYTES];
    build_pkcs1_em(em, k, hash);
    if (rsa_private_op(key, em, k, sig, k) != 0) return -1;
    *sig_len = k;
    return 0;
}


// Verify an RSA PKCS#1 v1.5 signature
int tls_rsa_verify(const RSAKey *pub, const uint8_t *hash, const uint8_t *sig, int sig_len) {
    int k = pub->n_len;
    if (sig_len != k || k > TLS_RSA_MODULUS_BYTES) return -1;
    uint8_t em[TLS_RSA_MODULUS_BYTES], expected[TLS_RSA_MODULUS_BYTES];
    if (rsa_public_op(pub, sig, sig_len, em, k) != 0) return -1;
    build_pkcs1_em(expected, k, hash);
    return memcmp(em, expected, (size_t)k) == 0 ? 0 : -1;
}


// Encode a DER (TLV) length
static int der_enc_len(uint8_t *out, int len) {
    if (len < 0x80) { out[0] = (uint8_t)len; return 1; }
    if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
    if (len < 0x10000) { out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)(len & 0xFF); return 3; }
    return 0;
}


// DER element header (tag and length)
static int der_header(uint8_t *out, uint8_t tag, int content_len) {
    out[0] = tag;
    int l = der_enc_len(out + 1, content_len);
    return 1 + l;
}


// Append a DER element with tag and content
static int der_push(uint8_t *out, int p, uint8_t tag, const uint8_t *content, int content_len) {
    int h = der_header(out + p, tag, content_len);
    if (content_len > 0) memcpy(out + p + h, content, (size_t)content_len);
    return p + h + content_len;
}


// Write an INTEGER in DER
static int der_integer(uint8_t *out, const uint8_t *val, int len) {
    int vlen = len;
    if (val[0] & 0x80) vlen++;
    int h = der_header(out, 0x02, vlen);
    int p = h;
    if (vlen > len) out[p++] = 0x00;
    memcpy(out + p, val, (size_t)len);
    return p + len;
}


// Read a DER element length
static int der_read_len(const uint8_t *in, int *p, int len) {
    if (*p + 1 > len) return -1;
    int l = in[(*p)++];
    if (l & 0x80) {
        int nb = l & 0x7F;
        if (nb < 1 || nb > 2 || *p + nb > len) return -1;
        l = 0;
        while (nb--) l = (l << 8) | in[(*p)++];
    }
    return l;
}


static const uint8_t OID_CN[3]  = { 0x55, 0x04, 0x03 };
static const uint8_t OID_C[3]   = { 0x55, 0x04, 0x06 };
static const uint8_t OID_L[3]   = { 0x55, 0x04, 0x07 };
static const uint8_t OID_ST[3]  = { 0x55, 0x04, 0x08 };
static const uint8_t OID_O[3]   = { 0x55, 0x04, 0x0a };
static const uint8_t OID_OU[3]  = { 0x55, 0x04, 0x0b };


// Check whether a string fits PrintableString
static int printable_ok(const char *s) {
    const char allowed[] = " '()+,-./:=?";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') continue;
        if (c >= 'a' && c <= 'z') continue;
        if (c >= '0' && c <= '9') continue;
        if (!strchr(allowed, (int)c)) return 0;
    }
    return 1;
}


// Encode an RDN (SET) in the X.509 Name
static int der_name_rdn(uint8_t *out, const uint8_t *oid, int oidlen, const char *value) {
    uint8_t atv[512];
    int p = 0;
    p = der_push(atv, p, 0x06, oid, oidlen);
    p = der_push(atv, p, printable_ok(value) ? 0x13 : 0x0c,
                 (const uint8_t *)value, (int)strlen(value));
    uint8_t seq[520];
    int s = der_push(seq, 0, 0x30, atv, p);
    return der_push(out, 0, 0x31, seq, s);
}


// Encode the subject Name from a CertSubject
static int der_subject_name(uint8_t *out, const CertSubject *subj) {
    uint8_t body[1100];
    int p = 0;
    if (subj) {
        if (subj->country[0])    p += der_name_rdn(body + p, OID_C,  3, subj->country);
        if (subj->state[0])      p += der_name_rdn(body + p, OID_ST, 3, subj->state);
        if (subj->locality[0])   p += der_name_rdn(body + p, OID_L,  3, subj->locality);
        if (subj->org[0])        p += der_name_rdn(body + p, OID_O,  3, subj->org);
        if (subj->org_unit[0])   p += der_name_rdn(body + p, OID_OU, 3, subj->org_unit);
        if (subj->common_name[0])p += der_name_rdn(body + p, OID_CN, 3, subj->common_name);
    }
    if (p == 0) p += der_name_rdn(body + p, OID_CN, 3, "ftps server");
    return der_push(out, 0, 0x30, body, p);
}


// Encode a time in DER (UTCTime or GeneralizedTime)
static int der_time(uint8_t *out, const struct tm *tm, int gen) {
    char buf[32];
    int l = gen ? (int)strftime(buf, sizeof(buf), "%Y%m%d%H%M%SZ", tm)
                : (int)strftime(buf, sizeof(buf), "%y%m%d%H%M%SZ", tm);
    if (l <= 0) return 0;
    return der_push(out, 0, gen ? 0x18 : 0x17, (const uint8_t *)buf, l);
}


// Build one X.509v3 Extension: SEQUENCE { OID, [critical], OCTET STRING }
static int der_extension(uint8_t *out, int p, const uint8_t *oid, int oid_len,
                         int critical, const uint8_t *value, int value_len) {
    uint8_t inner[520];
    int q = 0;
    q = der_push(inner, q, 0x06, oid, oid_len);
    if (critical) {
        uint8_t b = 0xFF;
        q = der_push(inner, q, 0x01, &b, 1);
    }
    q = der_push(inner, q, 0x04, value, value_len);
    return der_push(out, p, 0x30, inner, q);
}


/* Build the X.509v3 extensions for a self-signed server certificate:
   subjectAltName (DNS from CN + IP 127.0.0.1), basicConstraints (CA:FALSE),
   keyUsage (digitalSignature|keyEncipherment), extendedKeyUsage (serverAuth). */
static int der_build_extensions(uint8_t *out, int p, const CertSubject *subject) {
    static const uint8_t OID_SAN[3]        = { 0x55, 0x1d, 0x11 };
    static const uint8_t OID_BASIC[3]      = { 0x55, 0x1d, 0x13 };
    static const uint8_t OID_KU[3]         = { 0x55, 0x1d, 0x0f };
    static const uint8_t OID_EKU[3]        = { 0x55, 0x1d, 0x25 };
    static const uint8_t OID_SERVER_AUTH[8] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
    static const uint8_t IP_LOOPBACK[4]    = { 127, 0, 0, 1 };

    uint8_t ext_seq[600];
    int xp = 0;

    // subjectAltName: dNSName=<CN>, iPAddress=127.0.0.1
    {
        uint8_t gn[128];
        int gp = 0;
        const char *cn = (subject && subject->common_name[0]) ? subject->common_name : "localhost";
        gp = der_push(gn, gp, 0x82, (const uint8_t *)cn, (int)strlen(cn));
        gp = der_push(gn, gp, 0x87, IP_LOOPBACK, 4);
        uint8_t san[140];
        int sl = der_push(san, 0, 0x30, gn, gp);
        xp = der_extension(ext_seq, xp, OID_SAN, 3, 0, san, sl);
    }

    // basicConstraints: cA=FALSE (critical)
    {
        uint8_t bc[2] = { 0x30, 0x00 };
        xp = der_extension(ext_seq, xp, OID_BASIC, 3, 1, bc, 2);
    }

    // keyUsage: digitalSignature | keyEncipherment (critical)
    {
        uint8_t ku[4] = { 0x03, 0x02, 0x00, 0xa0 };
        xp = der_extension(ext_seq, xp, OID_KU, 3, 1, ku, 4);
    }

    // extendedKeyUsage: serverAuth
    {
        uint8_t eku_val[16];
        int ev = der_push(eku_val, 0, 0x06, OID_SERVER_AUTH, 8);
        uint8_t eku[24];
        int el = der_push(eku, 0, 0x30, eku_val, ev);
        xp = der_extension(ext_seq, xp, OID_EKU, 3, 0, eku, el);
    }

    // Extensions wrapped as [3] EXPLICIT
    uint8_t extns[620];
    int ex = der_push(extns, 0, 0x30, ext_seq, xp);
    return der_push(out, p, 0xA3, extns, ex);
}


// Generate a self-signed X.509 certificate with a custom subject
int tls_generate_self_signed_cert_ex(RSAKey *key, const CertSubject *subject,
                                     uint8_t *cert, int *cert_len) {
    if (!key || !key->is_private) return -1;
    static const uint8_t OID_SHA256_RSA[9] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
    static const uint8_t OID_RSA_ENCRYPT[9] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 };


    int days = subject ? subject->days : 0;
    if (days <= 0) days = 365;
    time_t now = time(NULL);
    time_t end = now + (time_t)days * 86400L;
    struct tm tmn = *gmtime(&now);
    struct tm tme = *gmtime(&end);
    int gen = (tmn.tm_year + 1900 >= 2050) || (tme.tm_year + 1900 >= 2050);


    uint8_t inner_sig[20];
    int ip = 0;
    ip = der_push(inner_sig, ip, 0x06, OID_SHA256_RSA, 9);
    inner_sig[ip++] = 0x05; inner_sig[ip++] = 0x00;
    uint8_t sigalg[24];
    int sa = der_push(sigalg, 0, 0x30, inner_sig, ip);


    uint8_t name[1100];
    int np = der_subject_name(name, subject);


    uint8_t oids[40];
    int ol = 0;
    ol = der_push(oids, ol, 0x06, OID_RSA_ENCRYPT, 9);
    oids[ol++] = 0x05; oids[ol++] = 0x00;
    uint8_t rsa_alg[48];
    int ra = der_push(rsa_alg, 0, 0x30, oids, ol);


    uint8_t rpk[700], rpk_seq[700];
    int rp = 0;
    rp += der_integer(rpk + rp, key->n, key->n_len);
    rp += der_integer(rpk + rp, key->e, key->e_len);
    int rs = der_push(rpk_seq, 0, 0x30, rpk, rp);


    uint8_t bit[700];
    bit[0] = 0x00;
    memcpy(bit + 1, rpk_seq, (size_t)rs);


    uint8_t spki_content[800];
    int sc = 0;
    memcpy(spki_content, rsa_alg, (size_t)ra); sc += ra;
    sc = der_push(spki_content, sc, 0x03, bit, rs + 1);
    uint8_t spki[800];
    int st = der_push(spki, 0, 0x30, spki_content, sc);


    uint8_t val[64], val_seq[80];
    int vp = 0;
    vp += der_time(val + vp, &tmn, gen);
    vp += der_time(val + vp, &tme, gen);
    int vs = der_push(val_seq, 0, 0x30, val, vp);


    uint8_t tbs[1900];
    int p = 0;
    static const uint8_t VERSION[3] = { 0x02, 0x01, 0x02 };
    p = der_push(tbs, p, 0xA0, VERSION, 3);
    uint8_t serial[8]; tls_random(serial, 8); serial[0] &= 0x7F;
    p += der_integer(tbs + p, serial, 8);
    memcpy(tbs + p, sigalg, (size_t)sa); p += sa;
    memcpy(tbs + p, name, (size_t)np); p += np;
    memcpy(tbs + p, val_seq, (size_t)vs); p += vs;
    memcpy(tbs + p, name, (size_t)np); p += np;
    memcpy(tbs + p, spki, (size_t)st); p += st;
    p = der_build_extensions(tbs, p, subject);

    uint8_t tbs_seq[2100];
    int tbs_len = der_push(tbs_seq, 0, 0x30, tbs, p);


    uint8_t hash[32];
    SHA256State sha;
    sha256_init(&sha); sha256_process(&sha, tbs_seq, tbs_len); sha256_done(&sha, hash);
    uint8_t sder[256]; int sder_len = 0;
    tls_rsa_sign(key, hash, sder, &sder_len);

    uint8_t sigbit[1 + 256];
    sigbit[0] = 0x00;
    memcpy(sigbit + 1, sder, (size_t)sder_len);

    uint8_t inner[3100];
    int ip2 = 0;
    memcpy(inner, tbs_seq, (size_t)tbs_len); ip2 = tbs_len;
    memcpy(inner + ip2, sigalg, (size_t)sa); ip2 += sa;
    ip2 = der_push(inner, ip2, 0x03, sigbit, sder_len + 1);
    int hdr = der_header(cert, 0x30, ip2);
    memcpy(cert + hdr, inner, (size_t)ip2);
    *cert_len = hdr + ip2;
    return 0;
}


// Generate a self-signed X.509 certificate (default subject)
int tls_generate_self_signed_cert(RSAKey *key, uint8_t *cert, int *cert_len) {
    static const CertSubject dflt = { "", "", "", "", "", "ftps server", 365 };
    return tls_generate_self_signed_cert_ex(key, &dflt, cert, cert_len);
}


// PRF based on HMAC-SHA256 (TLS 1.2)
static void tls_P_hash(const uint8_t *secret, int secret_len, const uint8_t *seed, int seed_len, uint8_t *output, int output_len) {
    HMACState hmac;
    uint8_t A[32]; int A_len = 32;
    hmac_sha256_init(&hmac, secret, secret_len); hmac_sha256_process(&hmac, seed, seed_len); hmac_sha256_done(&hmac, A, &A_len);
    while (output_len > 0) {
        hmac_sha256_init(&hmac, secret, secret_len); hmac_sha256_process(&hmac, A, A_len); hmac_sha256_process(&hmac, seed, seed_len);
        uint8_t tmp[32]; int tmp_len = 32; hmac_sha256_done(&hmac, tmp, &tmp_len);
        int copy_len = output_len < tmp_len ? output_len : tmp_len;
        memcpy(output, tmp, copy_len); output += copy_len; output_len -= copy_len;
        hmac_sha256_init(&hmac, secret, secret_len); hmac_sha256_process(&hmac, A, A_len); hmac_sha256_done(&hmac, A, &A_len);
    }
}


// TLS 1.2 PRF with label and seed
static void tls_prf(const uint8_t *secret, int secret_len, const char *label, const uint8_t *seed, int seed_len, uint8_t *output, int output_len) {
    int label_len = (int)strlen(label);
    int total_len = label_len + seed_len;
    uint8_t full_seed[128];
    memcpy(full_seed, label, label_len);
    memcpy(full_seed + label_len, seed, seed_len);
    tls_P_hash(secret, secret_len, full_seed, total_len, output, output_len);
}


// Compute the master secret (TLS 1.2)
static void derive_master_secret(TLSContext *ctx, const uint8_t *pre_master) {
    uint8_t seed[64];
    memcpy(seed, ctx->client_random, 32); memcpy(seed + 32, ctx->server_random, 32);
    tls_prf(pre_master, 32, "master secret", seed, 64, ctx->master_secret, TLS_RSA_MASTER_SIZE);
}


// Derive the key block and cipher keys (TLS 1.2)
static void derive_keys(TLSContext *ctx) {
    uint8_t seed[64];
    memcpy(seed, ctx->server_random, 32); memcpy(seed + 32, ctx->client_random, 32);
    int needed = 2 * (TLS_RSA_AES_BLOCK_SIZE + TLS_RSA_GCM_IV_LEN);
    uint8_t key_material[TLS_RSA_MAX_KEY_BYTES];
    tls_prf(ctx->master_secret, TLS_RSA_MASTER_SIZE, "key expansion", seed, 64, key_material, needed);
    int pos = 0;
    memcpy(ctx->client_write_key, key_material + pos, 16); pos += 16;
    memcpy(ctx->server_write_key, key_material + pos, 16); pos += 16;
    memcpy(ctx->client_write_iv, key_material + pos, 4); pos += 4;
    memcpy(ctx->server_write_iv, key_material + pos, 4); pos += 4;
    gcm_init(&ctx->client_gcm, ctx->client_write_key, 16);
    gcm_init(&ctx->server_gcm, ctx->server_write_key, 16);
    ctx->gcm_created = 1;
}


// Initialize a TLS context for a given version
int tls_init_context(TLSContext *ctx, int is_server, int version) {
    memset(ctx, 0, sizeof(TLSContext));
    ctx->is_server = is_server;
    switch (version) {
        case TLS_VERSION_13:
            ctx->tls13 = 1;
            ctx->cipher_suite = TLS13_CIPHER_SUITE;
            break;
        case TLS_VERSION_12:
            ctx->tls13 = 0;
            ctx->cipher_suite = TLS_RSA_CIPHER_SUITE;
            break;
        case TLS_VERSION_AUTO:
        default:
            ctx->tls13 = TLS_RSA_VERSION_AUTO;
            ctx->cipher_suite = TLS_RSA_CIPHER_SUITE;
            break;
    }
    ctx->group = TLS_RSA_CURVE_X25519;
    return 0;
}


// Initialize a TLS 1.3 context
int tls_init_context_13(TLSContext *ctx, int is_server) {
    return tls_init_context(ctx, is_server, TLS_VERSION_13);
}


// Initialize a TLS context with automatic version selection
int tls_init_context_auto(TLSContext *ctx, int is_server) {
    return tls_init_context(ctx, is_server, TLS_VERSION_AUTO);
}


// Report the negotiated TLS version (1.3 or 1.2)
int tls_negotiated_tls13(const TLSContext *ctx) { return ctx->tls13 == 1; }


// Check whether the handshake has finished
int tls_is_established(TLSContext *ctx) { return ctx->handshake_done; }


// Set the server RSA key in the context
int tls_set_rsa_key(TLSContext *ctx, const RSAKey *key) {
    memcpy(&ctx->static_rsa_key, key, sizeof(RSAKey));
    ctx->has_rsa_key = 1;
    return 0;
}


// Set the server certificate in the context
int tls_set_certificate(TLSContext *ctx, const uint8_t *cert, int cert_len) {
    if (!ctx || !cert) return -1;
    if (cert_len < 0 || cert_len > TLS_RSA_MAX_CERT_SIZE) return -1;
    memcpy(ctx->cert, cert, (size_t)cert_len);
    ctx->cert_len = cert_len;
    ctx->has_cert = 1;
    return 0;
}

// Set intermediate chain, stored as [u16 len][DER]... entries.
int tls_set_chain(TLSContext *ctx, const uint8_t *chain, int chain_len) {
    if (!ctx) return -1;
    if (chain_len < 0 || chain_len > TLS_RSA_MAX_CHAIN_SIZE) return -1;
    if (chain_len > 0 && !chain) return -1;
    // Validate entries so a corrupt chain cannot break the handshake builder.
    {
        int pos = 0;
        while (pos < chain_len) {
            if (pos + 2 > chain_len) return -1;
            int cl = ((int)chain[pos] << 8) | (int)chain[pos + 1];
            if (cl <= 0 || pos + 2 + cl > chain_len) return -1;
            pos += 2 + cl;
        }
        if (pos != chain_len) return -1;
    }
    if (chain_len > 0) memcpy(ctx->chain, chain, (size_t)chain_len);
    ctx->chain_len = chain_len;
    return 0;
}


static const char *BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


// Value of a base64 character
static int b64_val(char c) {
    const char *p = strchr(BASE64_TABLE, c);
    return p ? (int)(p - BASE64_TABLE) : -1;
}


// Decode a base64 string into bytes
static int base64_decode(const char *in, int in_len, uint8_t *out, int max_out) {
    int o = 0;
    int acc = 0, bits = 0;
    for (int i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) return -1;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= max_out) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return o;
}


/* Read up to max_len bytes of a file into buf using native OS APIs.
 * Returns the number of bytes read, or -1 if the file could not be opened. */
static long read_file_bytes(const char *path, char *buf, size_t max_len) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD r = 0;
    BOOL ok = ReadFile(h, buf, (DWORD)(max_len < 0xFFFFFFFFu ? max_len : 0xFFFFFFFFu), &r, NULL);
    CloseHandle(h);
    return ok ? (long)r : -1;
#else
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, max_len);
    close(fd);
    return r < 0 ? -1 : (long)r;
#endif
}

// Read a PEM file and decode it into DER
int tls_pem_to_der(const char *path, uint8_t *out, int *out_len, int max_out) {
    char buf[16384];
    long n = read_file_bytes(path, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = 0;

    char *start = buf;
    char *nl = strchr(start, '\n');
    if (nl) start = nl + 1;
    char *end = strstr(start, "-----");
    int body_len = (int)(end ? (end - start) : strlen(start));
    int dl = base64_decode(start, body_len, out, max_out);
    if (dl <= 0) return -1;
    *out_len = dl;
    return 0;
}

// Read a PEM file with leaf + chain: first CERTIFICATE -> leaf,
// remaining CERTIFICATE blocks -> chain ([u16 len][DER]...).
int tls_pem_to_chain_der(const char *path,
                         uint8_t *leaf, int *leaf_len, int leaf_max,
                         uint8_t *chain, int *chain_len, int chain_max) {
    static const char BEGIN_MARK[] = "-----BEGIN CERTIFICATE-----";
    static const char END_MARK[] = "-----END CERTIFICATE-----";
    char buf[32768];
    long n = read_file_bytes(path, buf, sizeof(buf) - 1);
    if (n <= 0 || !leaf || !leaf_len || !chain_len) return -1;
    buf[n] = 0;
    *leaf_len = 0;
    *chain_len = 0;
    int ncerts = 0;
    char *p = buf;
    while ((p = strstr(p, BEGIN_MARK)) != NULL) {
        char *body = p + sizeof(BEGIN_MARK) - 1;
        char *end = strstr(body, END_MARK);
        if (!end) return -1;
        if (ncerts == 0) {
            int dl = base64_decode(body, (int)(end - body), leaf, leaf_max);
            if (dl <= 0) return -1;
            *leaf_len = dl;
        } else {
            uint8_t tmp[TLS_RSA_MAX_CERT_SIZE];
            int dl = base64_decode(body, (int)(end - body), tmp, sizeof(tmp));
            if (dl <= 0 || dl > 0xFFFF) return -1;
            if (*chain_len + 2 + dl > chain_max) return -1;
            chain[*chain_len] = (uint8_t)((dl >> 8) & 0xFF);
            chain[*chain_len + 1] = (uint8_t)(dl & 0xFF);
            memcpy(chain + *chain_len + 2, tmp, (size_t)dl);
            *chain_len += 2 + dl;
        }
        ncerts++;
        p = end + sizeof(END_MARK) - 1;
    }
    return ncerts > 0 ? 0 : -1;
}


// Skip one TLV element in a DER buffer
static int der_skip_tlv(const uint8_t *p, int len, int *pos) {
    if (*pos >= len) return -1;
    (*pos)++;
    int clen = der_read_len(p, pos, len);
    if (clen < 0 || *pos + clen > len) return -1;
    *pos += clen;
    return 0;
}


// Read an INTEGER from DER
static int der_read_integer(const uint8_t *p, int len, int *pos, uint8_t *out, int max_out, int *out_len) {
    if (*pos >= len || p[*pos] != 0x02) return -1;
    (*pos)++;
    int vlen = der_read_len(p, pos, len);
    if (vlen < 1 || *pos + vlen > len) return -1;
    int cs = *pos, c = vlen;
    if (p[cs] == 0x00) { cs++; c--; }
    if (c < 0 || c > max_out) return -1;
    if (c > 0 && out) memcpy(out, p + cs, (size_t)c);
    *out_len = c;
    *pos += vlen;
    return 0;
}


// Parse a PKCS#1 key after the version field
static int parse_pkcs1_after_version(const uint8_t *p, int pos, int len, RSAKey *key) {
    int v;
    memset(key, 0, sizeof(RSAKey));
    if (der_read_integer(p, len, &pos, key->n, TLS_RSA_MODULUS_BYTES, &key->n_len) != 0) return -1;
    if (der_read_integer(p, len, &pos, key->e, (int)sizeof(key->e), &key->e_len) != 0) return -1;
    if (der_read_integer(p, len, &pos, key->d, TLS_RSA_MODULUS_BYTES, &v) != 0) return -1;
    key->is_private = 1;
    return 0;
}


// Parse a PKCS#1 private key
static int parse_pkcs1_private(const uint8_t *p, int pos, int len, RSAKey *key) {
    int v;
    if (der_read_integer(p, len, &pos, NULL, 0, &v) != 0) return -1;
    return parse_pkcs1_after_version(p, pos, len, key);
}


// Parse a private RSA key (PKCS#8/PKCS#1) from DER
int tls_rsa_parse_private_der(RSAKey *key, const uint8_t *der, int der_len) {
    if (der_len < 4 || der[0] != 0x30) return -1;
    int pos = 1;
    int outer = der_read_len(der, &pos, der_len);
    if (outer < 0 || pos + outer > der_len) return -1;
    int end = pos + outer;


    if (pos >= end || der[pos] != 0x02) return -1;
    if (der_skip_tlv(der, der_len, &pos) < 0) return -1;
    if (pos >= end) return -1;

    if (der[pos] == 0x02) {
        return parse_pkcs1_after_version(der, pos, der_len, key);
    }
    if (der[pos] != 0x30) return -1;

    if (der_skip_tlv(der, der_len, &pos) < 0) return -1;
    if (pos >= end || der[pos] != 0x04) return -1;
    pos++;
    int olen = der_read_len(der, &pos, der_len);
    if (olen < 2 || pos + olen > der_len) return -1;
    int inner = pos;
    if (inner >= der_len || der[inner] != 0x30) return -1;
    int ip = inner + 1;
    if (der_read_len(der, &ip, olen) < 0) return -1;
    return parse_pkcs1_private(der, ip, olen, key);
}


// Extract the public RSA key from a DER certificate
int tls_rsa_parse_public_der(RSAKey *key, const uint8_t *der, int der_len) {
    memset(key, 0, sizeof(RSAKey));
    for (int i = 0; i + 4 < der_len; i++) {
        const uint8_t *p = der + i;
        if (p[0] != 0x30) continue;
        int ip = 1;
        int sl = der_read_len(p, &ip, der_len - i);
        if (sl <= 0 || (i + ip + sl) > der_len) continue;
        int q = ip;
        if (p[q] != 0x02) continue;
        q++;
        int nl = der_read_len(p, &q, der_len - i);
        if (nl < 64 || nl > 257 || (q + nl) >= der_len) continue;
        int epos = q + nl;
        if (p[epos] != 0x02) continue;
        epos++;
        int el = der_read_len(p, &epos, der_len - i);
        if (el != 3 || epos + el > der_len) continue;
        if (!(p[epos] == 0x01 && p[epos + 1] == 0x00 && p[epos + 2] == 0x01)) continue;
        key->n_len = TLS_RSA_MODULUS_BYTES;
        memset(key->n, 0, TLS_RSA_MODULUS_BYTES);
        if (nl > TLS_RSA_MODULUS_BYTES) {
            memcpy(key->n, p + q + (nl - TLS_RSA_MODULUS_BYTES), TLS_RSA_MODULUS_BYTES);
        } else {
            memcpy(key->n + (TLS_RSA_MODULUS_BYTES - nl), p + q, (size_t)nl);
        }
        key->e_len = 3;
        memcpy(key->e, p + epos, 3);
        key->is_private = 0;
        return 0;
    }
    return -1;
}


// Encrypt a TLS record (AES-GCM)
static int encrypt_record(TLSContext *ctx, uint8_t type, const uint8_t *pt_in, int pt_len, uint8_t *out, int *out_len) {
    if (!ctx->gcm_created) return -1;
    GCMState *gcm = ctx->is_server ? &ctx->server_gcm : &ctx->client_gcm;
    const uint8_t *iv = ctx->is_server ? ctx->server_write_iv : ctx->client_write_iv;
    uint64_t seq = ctx->is_server ? ctx->server_sequence : ctx->client_sequence;
    uint8_t aad[13]; w64(aad, seq); aad[8] = type; aad[9] = 0x03; aad[10] = 0x03; w16(aad + 11, pt_len);
    uint8_t exp_iv[8]; tls_random(exp_iv, 8);
    uint8_t full_iv[12]; memcpy(full_iv, iv, 4); memcpy(full_iv + 4, exp_iv, 8);
    gcm_reset(gcm); gcm_add_iv(gcm, full_iv, 12); gcm_add_aad(gcm, aad, 13);
    uint8_t *ct = out + 5 + 8;
    gcm_process(gcm, (uint8_t *)pt_in, ct, pt_len, 0);
    uint8_t tag[16]; int tag_len = 16; gcm_done(gcm, tag, &tag_len);
    out[0] = type; out[1] = 0x03; out[2] = 0x03; w16(out + 3, 8 + pt_len + 16);
    memcpy(out + 5, exp_iv, 8); memcpy(ct + pt_len, tag, 16);
    *out_len = 5 + 8 + pt_len + 16;
    if (ctx->is_server) ctx->server_sequence++; else ctx->client_sequence++;
    return 0;
}


// Decrypt a single TLS record
int decrypt_record(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *pt, int *pt_len) {
    if (in_len < 5) return -1;
    if (!ctx->gcm_created) return -1;
    uint16_t rec_len = r16(in + 3);
    if (rec_len < 8 + 16) return -1;
    if (in_len < 5 + rec_len) return -1;
    GCMState *gcm = ctx->is_server ? &ctx->client_gcm : &ctx->server_gcm;
    const uint8_t *iv = ctx->is_server ? ctx->client_write_iv : ctx->server_write_iv;
    uint64_t seq = ctx->is_server ? ctx->client_sequence : ctx->server_sequence;
    uint8_t exp_iv[8]; memcpy(exp_iv, in + 5, 8);
    uint8_t full_iv[12]; memcpy(full_iv, iv, 4); memcpy(full_iv + 4, exp_iv, 8);
    uint8_t aad[13]; w64(aad, seq); aad[8] = in[0]; aad[9] = in[1]; aad[10] = in[2];
    int data_len = rec_len - 8 - 16;
    w16(aad + 11, data_len);
    gcm_reset(gcm); gcm_add_iv(gcm, full_iv, 12); gcm_add_aad(gcm, aad, 13);
    gcm_process(gcm, pt, (uint8_t *)(in + 5 + 8), data_len, 1);
    uint8_t tag[16]; int tag_len = 16; gcm_done(gcm, tag, &tag_len);
    if (memcmp(tag, in + 5 + 8 + data_len, 16) != 0) return -1;
    *pt_len = data_len;
    if (ctx->is_server) ctx->client_sequence++; else ctx->server_sequence++;
    return 0;
}


// Save remaining input bytes in the receive buffer
static void stash_leftover(TLSContext *ctx, const uint8_t *in, int consumed, int in_len) {
    ctx->recv_raw.len = 0;
    int left = in_len - consumed;
    if (in && left > 0) {
        if (left > (int)sizeof(ctx->recv_raw.data)) left = (int)sizeof(ctx->recv_raw.data);
        memcpy(ctx->recv_raw.data, in + consumed, (size_t)left);
        ctx->recv_raw.len = (uint32_t)left;
    }
}


// Add the SNI extension to a ClientHello
static int client_hello_add_sni(TLSContext *ctx, uint8_t *out, int pos) {
    if (ctx->server_name_len <= 0 || ctx->server_name_len > 255) return pos;
    w16(out + pos, 0x0000); pos += 2;
    w16(out + pos, (uint16_t)(5 + ctx->server_name_len)); pos += 2;
    w16(out + pos, (uint16_t)(ctx->server_name_len + 3)); pos += 2;
    out[pos++] = 0;
    w16(out + pos, (uint16_t)ctx->server_name_len); pos += 2;
    memcpy(out + pos, ctx->server_name, (size_t)ctx->server_name_len); pos += ctx->server_name_len;
    return pos;
}


// Add the ALPN extension to a TLS 1.3 ClientHello
static int tls13_client_hello_add_alpn(uint8_t *out, int pos) {

    w16(out + pos, 0x0010); pos += 2;
    w16(out + pos, 11); pos += 2;
    w16(out + pos, 9); pos += 2;
    out[pos++] = 8;
    memcpy(out + pos, "http/1.1", 8); pos += 8;
    return pos;
}


// Enable or disable peer certificate verification
int tls_set_peer_verify(TLSContext *ctx, int enable) {
    if (!ctx) return -1;
    ctx->peer_verify_enabled = enable ? 1 : 0;
    return 0;
}


// Set the server name for SNI
int tls_set_server_name(TLSContext *ctx, const char *name, int name_len) {
    if (!ctx || !name || name_len <= 0) {
        if (ctx) ctx->server_name_len = 0;
        return -1;
    }
    if (name_len >= (int)sizeof(ctx->server_name)) name_len = (int)sizeof(ctx->server_name) - 1;
    memcpy(ctx->server_name, name, (size_t)name_len);
    ctx->server_name[name_len] = '\0';
    ctx->server_name_len = name_len;
    return 0;
}


// Build a ClientHello (TLS 1.2)
static int build_client_hello(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_CLIENT_HELLO;
    int hl_pos = pos; pos += 3;
    w16(out + pos, TLS_RSA_VERSION_12); pos += 2;
    tls_random(ctx->client_random, 32);
    uint32_t now = (uint32_t)time(NULL); w32(ctx->client_random, now);
    memcpy(out + pos, ctx->client_random, 32); pos += 32;
    out[pos++] = 0;
    w16(out + pos, 2); pos += 2;
    w16(out + pos, TLS_RSA_CIPHER_SUITE); pos += 2;
    out[pos++] = 1; out[pos++] = 0;
    int el_pos = pos; pos += 2;

    w16(out + pos, 0x000A); pos += 2; w16(out + pos, 6); pos += 2;
    w16(out + pos, 4); pos += 2; w16(out + pos, TLS_RSA_CURVE_X25519); pos += 2;
    w16(out + pos, TLS_RSA_CURVE_SECP256R1); pos += 2;

    w16(out + pos, 0x000B); pos += 2; w16(out + pos, 2); pos += 2;
    out[pos++] = 1; out[pos++] = 0;

    w16(out + pos, 0x000D); pos += 2; w16(out + pos, 10); pos += 2;
    w16(out + pos, 8); pos += 2;
    w16(out + pos, 0x0403); pos += 2;
    w16(out + pos, 0x0503); pos += 2;
    w16(out + pos, TLS_RSA13_SIG_RSA_PSS_SHA256); pos += 2;
    w16(out + pos, TLS_RSA_SIG_RSA_SHA256); pos += 2;
    pos = client_hello_add_sni(ctx, out, pos);
    pos = tls13_client_hello_add_alpn(out, pos);
    w16(out + el_pos, pos - el_pos - 2);
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Check whether a ClientHello has an extension
static int client_hello_has_extension(const uint8_t *hs, int rec_len, uint16_t wanted) {
    if (rec_len < 4) return 0;
    int pos = 4;
    pos += 2 + 32;
    if (pos >= rec_len) return 0;
    int sid_len = hs[pos++];
    if (pos + sid_len > rec_len) return 0; pos += sid_len;
    if (pos + 2 > rec_len) return 0;
    int cs_len = (hs[pos] << 8) | hs[pos + 1]; pos += 2;
    if (pos + cs_len > rec_len) return 0; pos += cs_len;
    if (pos >= rec_len) return 0;
    int comp_len = hs[pos++];
    if (pos + comp_len > rec_len) return 0; pos += comp_len;
    if (pos + 2 > rec_len) return 0;
    int ext_total = (hs[pos] << 8) | hs[pos + 1]; pos += 2;
    int end = pos + ext_total;
    if (end > rec_len) return 0;
    while (pos + 4 <= end) {
        uint16_t et = (hs[pos] << 8) | hs[pos + 1];
        int el = (hs[pos + 2] << 8) | hs[pos + 3];
        pos += 4;
        if (pos + el > end) return 0;
        if (et == wanted) return 1;
        pos += el;
    }
    return 0;
}


// Build a ServerHello (TLS 1.2)
static int build_server_hello(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_SERVER_HELLO;
    int hl_pos = pos; pos += 3;
    w16(out + pos, TLS_RSA_VERSION_12); pos += 2;
    tls_random(ctx->server_random, 32);
    uint32_t now = (uint32_t)time(NULL); w32(ctx->server_random, now);
    memcpy(out + pos, ctx->server_random, 32); pos += 32;
    ctx->session_id_len = 32; tls_random(ctx->session_id, 32);
    out[pos++] = ctx->session_id_len; memcpy(out + pos, ctx->session_id, 32); pos += 32;
    w16(out + pos, TLS_RSA_CIPHER_SUITE); pos += 2;
    out[pos++] = 0;
    int el_pos = pos; pos += 2;
    {
        w16(out + pos, 0xFF01); pos += 2;
        w16(out + pos, 1); pos += 2;
        out[pos++] = 0;
    }
    w16(out + el_pos, pos - el_pos - 2);
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Build a Certificate message (TLS 1.2): leaf + intermediates from ctx->chain.
static int build_certificate(TLSContext *ctx, uint8_t *out, int out_max, int *out_len) {
    int pos = 0;
    if (out_max < 12 + ctx->cert_len + ctx->chain_len + 64) return -1;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_CERTIFICATE;
    int hl_pos = pos; pos += 3;
    int list_pos = pos; pos += 3;
    uint32_t cl = (uint32_t)ctx->cert_len;
    out[pos++] = (uint8_t)((cl >> 16) & 0xFF); out[pos++] = (uint8_t)((cl >> 8) & 0xFF); out[pos++] = (uint8_t)(cl & 0xFF);
    memcpy(out + pos, ctx->cert, (size_t)ctx->cert_len); pos += ctx->cert_len;
    // Append intermediates: chain holds [u16 len][DER]... entries.
    {
        int cp = 0;
        while (cp + 2 <= ctx->chain_len) {
            int il = ((int)(uint8_t)ctx->chain[cp] << 8) | (int)(uint8_t)ctx->chain[cp + 1];
            if (il <= 0 || cp + 2 + il > ctx->chain_len) break;
            uint32_t uil = (uint32_t)il;
            out[pos++] = (uint8_t)((uil >> 16) & 0xFF);
            out[pos++] = (uint8_t)((uil >> 8) & 0xFF);
            out[pos++] = (uint8_t)(uil & 0xFF);
            memcpy(out + pos, ctx->chain + cp + 2, (size_t)il);
            pos += il;
            cp += 2 + il;
        }
    }
    uint32_t list_len = (uint32_t)(pos - list_pos - 3);
    out[list_pos] = (uint8_t)((list_len >> 16) & 0xFF);
    out[list_pos + 1] = (uint8_t)((list_len >> 8) & 0xFF);
    out[list_pos + 2] = (uint8_t)(list_len & 0xFF);
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (uint8_t)((hs_len >> 16) & 0xFF); out[hl_pos + 1] = (uint8_t)((hs_len >> 8) & 0xFF); out[hl_pos + 2] = (uint8_t)(hs_len & 0xFF);
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Build a ServerKeyExchange message
static int build_server_key_exchange(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_SERVER_KEY_EXCHANGE;
    int hl_pos = pos; pos += 3;
    int params_start = pos;
    if (ctx->group == TLS_RSA_CURVE_X25519) {
        out[pos++] = 0x03;
        w16(out + pos, TLS_RSA_CURVE_X25519); pos += 2;
        out[pos++] = TLS_RSA_X25519_KEY_SIZE;
        tls_generate_x25519_key(&ctx->local_x25519_key);
        memcpy(out + pos, ctx->local_x25519_key.pub, TLS_RSA_X25519_KEY_SIZE); pos += TLS_RSA_X25519_KEY_SIZE;
    } else {
        out[pos++] = 0x03;
        w16(out + pos, TLS_RSA_CURVE_SECP256R1); pos += 2;
        tls_generate_p256_key(&ctx->local_ec_key);
        out[pos++] = 65;
        out[pos++] = 0x04;
        memcpy(out + pos, ctx->local_ec_key.x, 32); pos += 32;
        memcpy(out + pos, ctx->local_ec_key.y, 32); pos += 32;
    }

    uint8_t hash[32]; SHA256State sha;
    sha256_init(&sha); sha256_process(&sha, ctx->client_random, 32);
    sha256_process(&sha, ctx->server_random, 32);
    sha256_process(&sha, out + params_start, pos - params_start);
    sha256_done(&sha, hash);
    uint8_t sig[TLS_RSA_MODULUS_BYTES]; int sig_len = 0;
    tls_rsa_sign(&ctx->static_rsa_key, hash, sig, &sig_len);
    w16(out + pos, TLS_RSA_SIG_RSA_SHA256); pos += 2;
    w16(out + pos, (uint16_t)sig_len); pos += 2;
    memcpy(out + pos, sig, (size_t)sig_len); pos += sig_len;
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Build a ServerHelloDone message
static int build_server_hello_done(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_SERVER_HELLO_DONE;
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Build a ClientKeyExchange message
static int build_client_key_exchange(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_CLIENT_KEY_EXCHANGE;
    int hl_pos = pos; pos += 3;
    if (ctx->group == TLS_RSA_CURVE_X25519) {
        tls_generate_x25519_key(&ctx->local_x25519_key);
        out[pos++] = TLS_RSA_X25519_KEY_SIZE;
        memcpy(out + pos, ctx->local_x25519_key.pub, TLS_RSA_X25519_KEY_SIZE); pos += TLS_RSA_X25519_KEY_SIZE;
        tls_x25519_shared_secret(ctx->local_x25519_key.priv, ctx->remote_x25519_pub, ctx->ecdh_shared);
    } else {
        tls_generate_p256_key(&ctx->local_ec_key);
        out[pos++] = 65;
        out[pos++] = 0x04;
        memcpy(out + pos, ctx->local_ec_key.x, 32); pos += 32;
        memcpy(out + pos, ctx->local_ec_key.y, 32); pos += 32;
        ECPoint remote, result;
        memcpy(remote.x, ctx->remote_ec_ecdh_key.x, 32);
        memcpy(remote.y, ctx->remote_ec_ecdh_key.y, 32); remote.infinity = 0;
        ec_mul(&result, ctx->local_ec_key.k, &remote);
        memcpy(ctx->ecdh_shared, result.x, 32);
    }
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Build a ChangeCipherSpec message
static int build_change_cipher_spec(TLSContext *ctx, uint8_t *out, int *out_len) {
    out[0] = TLS_RSA_CHANGE_CIPHER; out[1] = 0x03; out[2] = 0x03;
    out[3] = 0; out[4] = 1; out[5] = 1;
    *out_len = 6;
    return 0;
}


// Build a Finished message
static int build_finished(TLSContext *ctx, uint8_t *out, int *out_len, uint8_t *plain, int *plain_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS_RSA_HS_FINISHED;
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 12;
    SHA256State cp = ctx->handshake_hash;
    uint8_t hash[32]; sha256_done(&cp, hash);
    uint8_t verify[12];
    tls_prf(ctx->master_secret, TLS_RSA_MASTER_SIZE,
             ctx->is_server ? "server finished" : "client finished", hash, 32, verify, 12);
    memcpy(out + pos, verify, 12); pos += 12;
    w16(out + rl_pos, pos - rl_pos - 2);
    if (plain) { memcpy(plain, out + 5, pos - 5); *plain_len = pos - 5; }
    uint8_t encrypted[512]; int enc_len;
    encrypt_record(ctx, TLS_RSA_HANDSHAKE, out + 5, pos - 5, encrypted, &enc_len);
    memcpy(out, encrypted, enc_len); *out_len = enc_len;
    return 0;
}


// Parse a ServerHello (TLS 1.2)
static int parse_server_hello(TLSContext *ctx, const uint8_t *data, int len) {
    if (len < 42) return -1;
    int pos = 4;
    pos += 2;
    memcpy(ctx->server_random, data + pos, 32); pos += 32;
    uint8_t sid_len = data[pos++]; pos += sid_len;
    ctx->cipher_suite = r16(data + pos); pos += 2;
    if (ctx->cipher_suite != TLS_RSA_CIPHER_SUITE) return -1;
    pos += 1;
    return 0;
}


// Parse a Certificate message
static int parse_certificate(TLSContext *ctx, const uint8_t *data, int len) {
    if (len < 10) return -1;
    int pos = 4;
    if (pos + 3 > len) return -1;
    uint32_t list_len = ((uint32_t)data[pos] << 16) | ((uint32_t)data[pos + 1] << 8) | data[pos + 2]; pos += 3;
    if (pos + 3 > len || list_len > (uint32_t)(len - pos)) return -1;
    uint32_t cert_len = ((uint32_t)data[pos] << 16) | ((uint32_t)data[pos + 1] << 8) | data[pos + 2]; pos += 3;
    if (cert_len > (uint32_t)(len - pos)) return -1;

    for (uint32_t i = 0; i + 4 < cert_len; i++) {
        const uint8_t *p = data + pos + i;
        if (p[0] != 0x30) continue;
        int ip = 1;
        int sl = der_read_len(p, &ip, (int)(cert_len - i));
        if (sl <= 0 || (int)(i + ip + sl) > (int)cert_len) continue;
        int q = ip;
        if (p[q] != 0x02) continue;
        q++;
        int nl = der_read_len(p, &q, (int)(cert_len - i));
        if (nl < 64 || nl > 257 || (int)(q + nl) >= (int)cert_len) continue;
        int epos = q + nl;
        if (p[epos] != 0x02) continue;
        epos++;
        int el = der_read_len(p, &epos, (int)(cert_len - i));
        if (el != 3 || epos + el > (int)cert_len) continue;
        if (!(p[epos] == 0x01 && p[epos + 1] == 0x00 && p[epos + 2] == 0x01)) continue;
        ctx->remote_rsa_key.n_len = TLS_RSA_MODULUS_BYTES;
        memset(ctx->remote_rsa_key.n, 0, TLS_RSA_MODULUS_BYTES);
        if (nl > TLS_RSA_MODULUS_BYTES) {
            memcpy(ctx->remote_rsa_key.n, p + q + (nl - TLS_RSA_MODULUS_BYTES), TLS_RSA_MODULUS_BYTES);
        } else {
            memcpy(ctx->remote_rsa_key.n + (TLS_RSA_MODULUS_BYTES - nl), p + q, (size_t)nl);
        }
        ctx->remote_rsa_key.e_len = 3;
        memcpy(ctx->remote_rsa_key.e, p + epos, 3);
        ctx->remote_rsa_key.is_private = 0;
        return 0;
    }
    return -1;
}


// Parse a ServerKeyExchange message
static int parse_server_key_exchange(TLSContext *ctx, const uint8_t *data, int len, int verify_signature) {
    if (len < 4) return -1;
    int pos = 4;
    if (data[pos++] != 0x03) return -1;
    uint16_t curve = r16(data + pos); pos += 2;
    if (curve == TLS_RSA_CURVE_X25519) {
        uint8_t pk_len = data[pos++];
        if (pk_len != TLS_RSA_X25519_KEY_SIZE) return -1;
        memcpy(ctx->remote_x25519_pub, data + pos, TLS_RSA_X25519_KEY_SIZE);
        ctx->group = TLS_RSA_CURVE_X25519;
        pos += TLS_RSA_X25519_KEY_SIZE;
    } else if (curve == TLS_RSA_CURVE_SECP256R1) {
        uint8_t pk_len = data[pos++];
        if (pk_len != 65 || data[pos] != 0x04) return -1;
        pos++;
        memcpy(ctx->remote_ec_ecdh_key.x, data + pos, 32); pos += 32;
        memcpy(ctx->remote_ec_ecdh_key.y, data + pos, 32); pos += 32;
        ctx->remote_ec_ecdh_key.is_private = 0;
        ctx->group = TLS_RSA_CURVE_SECP256R1;
    } else {
        return -1;
    }
    int params_end = pos;
    if (!verify_signature) return 0;
    uint16_t sig_algo = r16(data + pos); pos += 2;
    if (sig_algo != TLS_RSA_SIG_RSA_SHA256) return -1;
    uint16_t sig_len = r16(data + pos); pos += 2;
    if (pos + sig_len > len) return -1;
    uint8_t hash[32]; SHA256State sha;
    sha256_init(&sha);
    sha256_process(&sha, ctx->client_random, 32);
    sha256_process(&sha, ctx->server_random, 32);
    sha256_process(&sha, data + 4, params_end - 4);
    sha256_done(&sha, hash);
    if (tls_rsa_verify(&ctx->remote_rsa_key, hash, data + pos, sig_len) != 0) return -1;
    pos += sig_len;
    return 0;
}


// Parse a ClientKeyExchange message
static int parse_client_key_exchange(TLSContext *ctx, const uint8_t *data, int len) {
    if (len < 4) return -1;
    int pos = 4;
    if (ctx->group == TLS_RSA_CURVE_X25519) {
        uint8_t pk_len = data[pos++];
        if (pk_len != TLS_RSA_X25519_KEY_SIZE) return -1;
        memcpy(ctx->remote_x25519_pub, data + pos, TLS_RSA_X25519_KEY_SIZE);
    } else {
        uint8_t pk_len = data[pos++];
        if (pk_len != 65 || data[pos] != 0x04) return -1;
        pos++;
        memcpy(ctx->remote_ec_ecdh_key.x, data + pos, 32); pos += 32;
        memcpy(ctx->remote_ec_ecdh_key.y, data + pos, 32); pos += 32;
        ctx->remote_ec_ecdh_key.is_private = 0;
    }
    return 0;
}


// Parse a Finished message
static int parse_finished(TLSContext *ctx, const uint8_t *data, int len) {
    if (len < 16) return -1;
    if (data[0] != TLS_RSA_HS_FINISHED) return -1;
    SHA256State cp = ctx->handshake_hash;
    uint8_t hash[32]; sha256_done(&cp, hash);
    uint8_t expected[12];
    tls_prf(ctx->master_secret, TLS_RSA_MASTER_SIZE,
             ctx->is_server ? "client finished" : "server finished", hash, 32, expected, 12);
    return (memcmp(data + 4, expected, 12) == 0) ? 0 : -1;
}


static const uint8_t T13_EMPTY_HASH[32] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,
    0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
    0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};


// HKDF-Extract (RFC 5869)
static void hkdf_extract(const uint8_t *salt, int salt_len, const uint8_t *ikm, int ikm_len, uint8_t *prk) {
    uint8_t zero[32] = {0};
    if (salt_len == 0) { salt = zero; salt_len = 32; }
    HMACState h;
    hmac_sha256_init(&h, salt, salt_len);
    hmac_sha256_process(&h, ikm, ikm_len);
    int l = 32;
    hmac_sha256_done(&h, prk, &l);
}


// HKDF-Expand (RFC 5869)
static void hkdf_expand(const uint8_t *prk, const uint8_t *info, int info_len, uint8_t *out, int out_len) {
    HMACState h;
    uint8_t T[32], block[96];
    int T_len = 0, produced = 0, counter = 1;
    while (produced < out_len) {
        int n = 0;
        if (T_len) { memcpy(block, T, T_len); n = T_len; }
        memcpy(block + n, info, info_len); n += info_len;
        block[n++] = (uint8_t)counter++;
        hmac_sha256_init(&h, prk, 32);
        hmac_sha256_process(&h, block, n);
        int tl = 32; hmac_sha256_done(&h, T, &tl);
        T_len = 32;
        int take = (out_len - produced) < 32 ? (out_len - produced) : 32;
        memcpy(out + produced, T, take);
        produced += take;
    }
}


// HKDF-Expand-Label (RFC 8446)
static void hkdf_expand_label(const uint8_t *secret, const char *label, const uint8_t *ctx, int ctx_len, uint8_t *out, int out_len) {
    static const char prefix[] = "tls13 ";
    uint8_t info[96];
    int info_len = 0;
    int lab_len = (int)strlen(label);
    info[info_len++] = (uint8_t)(out_len >> 8);
    info[info_len++] = (uint8_t)(out_len & 0xFF);
    info[info_len++] = (uint8_t)(sizeof(prefix) - 1 + lab_len);
    memcpy(info + info_len, prefix, sizeof(prefix) - 1); info_len += sizeof(prefix) - 1;
    memcpy(info + info_len, label, lab_len); info_len += lab_len;
    info[info_len++] = (uint8_t)ctx_len;
    if (ctx_len > 0) { memcpy(info + info_len, ctx, ctx_len); info_len += ctx_len; }
    hkdf_expand(secret, info, info_len, out, out_len);
}


// Derive a TLS 1.3 level secret
static void tls13_derive_secret(const uint8_t *secret, const char *label, const uint8_t *transcript_hash, uint8_t *out) {
    hkdf_expand_label(secret, label, transcript_hash, 32, out, 32);
}


// Derive TLS 1.3 handshake keys
static void tls13_derive_handshake_keys(TLSContext *ctx) {
    uint8_t zero[32] = {0}, early[32], derived[32], hs_secret[32], hash[32];
    hkdf_extract(zero, 32, zero, 32, early);
    tls13_derive_secret(early, "derived", T13_EMPTY_HASH, derived);
    hkdf_extract(derived, 32, ctx->ecdh_shared, 32, hs_secret);
    memcpy(ctx->t13_hs_secret, hs_secret, 32);
    SHA256State cp = ctx->handshake_hash; uint8_t hash2[32]; sha256_done(&cp, hash2);
    uint8_t c_ts[32], s_ts[32];
    tls13_derive_secret(hs_secret, "c hs traffic", hash2, c_ts);
    tls13_derive_secret(hs_secret, "s hs traffic", hash2, s_ts);
    hkdf_expand_label(c_ts, "key", NULL, 0, ctx->c_hs_key, 16);
    hkdf_expand_label(c_ts, "iv", NULL, 0, ctx->c_hs_iv, 12);
    hkdf_expand_label(c_ts, "finished", NULL, 0, ctx->c_hs_finish_key, 32);
    hkdf_expand_label(s_ts, "key", NULL, 0, ctx->s_hs_key, 16);
    hkdf_expand_label(s_ts, "iv", NULL, 0, ctx->s_hs_iv, 12);
    hkdf_expand_label(s_ts, "finished", NULL, 0, ctx->s_hs_finish_key, 32);
}


// Derive TLS 1.3 application keys
static void tls13_derive_application_keys(TLSContext *ctx, const uint8_t *traffic_hash) {
    uint8_t zero[32] = {0}, derived[32], master[32], c_ts[32], s_ts[32];
    tls13_derive_secret(ctx->t13_hs_secret, "derived", T13_EMPTY_HASH, derived);
    hkdf_extract(derived, 32, zero, 32, master);
    tls13_derive_secret(master, "c ap traffic", traffic_hash, c_ts);
    tls13_derive_secret(master, "s ap traffic", traffic_hash, s_ts);
    hkdf_expand_label(c_ts, "key", NULL, 0, ctx->c_ap_key, 16);
    hkdf_expand_label(c_ts, "iv", NULL, 0, ctx->c_ap_iv, 12);
    hkdf_expand_label(s_ts, "key", NULL, 0, ctx->s_ap_key, 16);
    hkdf_expand_label(s_ts, "iv", NULL, 0, ctx->s_ap_iv, 12);
}


// Verify the Finished message (TLS 1.3)
static void tls13_finished_verify(const uint8_t *finish_key, const uint8_t *transcript_hash, uint8_t *verify) {
    HMACState h;
    hmac_sha256_init(&h, finish_key, 32);
    hmac_sha256_process(&h, transcript_hash, 32);
    int l = 32;
    hmac_sha256_done(&h, verify, &l);
}


// Select the TLS 1.3 encryption key for sending
static void tls13_select_send(TLSContext *ctx, const uint8_t **key, const uint8_t **iv, uint64_t *seq) {
    if (ctx->t13_app_send) {
        *key = ctx->is_server ? ctx->s_ap_key : ctx->c_ap_key;
        *iv  = ctx->is_server ? ctx->s_ap_iv  : ctx->c_ap_iv;
        *seq = ctx->t13_app_send_seq;
    } else {
        *key = ctx->is_server ? ctx->s_hs_key : ctx->c_hs_key;
        *iv  = ctx->is_server ? ctx->s_hs_iv  : ctx->c_hs_iv;
        *seq = ctx->t13_send_seq;
    }
}


// Select the TLS 1.3 encryption key for receiving
static void tls13_select_recv(TLSContext *ctx, const uint8_t **key, const uint8_t **iv, uint64_t *seq) {
    if (ctx->t13_app_recv) {
        *key = ctx->is_server ? ctx->c_ap_key : ctx->s_ap_key;
        *iv  = ctx->is_server ? ctx->c_ap_iv  : ctx->s_ap_iv;
        *seq = ctx->t13_app_recv_seq;
    } else {
        *key = ctx->is_server ? ctx->c_hs_key : ctx->s_hs_key;
        *iv  = ctx->is_server ? ctx->c_hs_iv  : ctx->s_hs_iv;
        *seq = ctx->t13_recv_seq;
    }
}


// Advance the TLS 1.3 send counter
static void tls13_advance_send(TLSContext *ctx) {
    if (ctx->t13_app_send) ctx->t13_app_send_seq++; else ctx->t13_send_seq++;
}


// Advance the TLS 1.3 receive counter
static void tls13_advance_recv(TLSContext *ctx) {
    if (ctx->t13_app_recv) ctx->t13_app_recv_seq++; else ctx->t13_recv_seq++;
}


// Encrypt a TLS 1.3 record
static int tls13_encrypt_record(TLSContext *ctx, uint8_t inner_type, const uint8_t *pt, int pt_len, uint8_t *out, int *out_len) {
    if (pt_len + 1 + 16 > TLS_RSA_MAX_BUFFER) return -1;
    const uint8_t *key, *iv; uint64_t seq;
    tls13_select_send(ctx, &key, &iv, &seq);
    uint8_t plain[TLS_RSA_MAX_BUFFER]; memcpy(plain, pt, pt_len); plain[pt_len] = inner_type;
    int total = pt_len + 1;
    uint8_t nonce[12]; memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[4 + i] ^= (uint8_t)(seq >> (8 * (7 - i)));
    uint8_t aad[5] = { TLS_RSA_APPLICATION_DATA, 0x03, 0x03, (uint8_t)((total + 16) >> 8), (uint8_t)((total + 16) & 0xFF) };
    GCMState gcm; gcm_init(&gcm, key, 16); gcm_reset(&gcm);
    gcm_add_iv(&gcm, nonce, 12); gcm_add_aad(&gcm, aad, 5);
    gcm_process(&gcm, plain, out + 5, total, 0);
    uint8_t tag[16]; int tl = 16; gcm_done(&gcm, tag, &tl);
    out[0] = TLS_RSA_APPLICATION_DATA; out[1] = 0x03; out[2] = 0x03; w16(out + 3, total + 16);
    memcpy(out + 5 + total, tag, 16);
    *out_len = 5 + total + 16;
    tls13_advance_send(ctx);
    return 0;
}


// Decrypt a TLS 1.3 record
static int tls13_decrypt_record(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *pt, int *pt_len, uint8_t *inner_type) {
    if (in_len < 5 + 16) return -1;
    uint16_t rec_len = r16(in + 3);
    if (5 + rec_len > in_len) return -1;
    int total = rec_len - 16;
    if (total < 1) return -1;
    const uint8_t *key, *iv; uint64_t seq;
    tls13_select_recv(ctx, &key, &iv, &seq);
    uint8_t nonce[12]; memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) nonce[4 + i] ^= (uint8_t)(seq >> (8 * (7 - i)));
    uint8_t aad[5] = { in[0], in[1], in[2], in[3], in[4] };
    GCMState gcm; gcm_init(&gcm, key, 16); gcm_reset(&gcm);
    gcm_add_iv(&gcm, nonce, 12); gcm_add_aad(&gcm, aad, 5);
    gcm_process(&gcm, pt, (uint8_t *)(in + 5), total, 1);
    uint8_t tag[16]; int tl = 16; gcm_done(&gcm, tag, &tl);
    if (memcmp(tag, in + 5 + total, 16) != 0) return -1;
    *inner_type = pt[total - 1];
    *pt_len = total - 1;
    tls13_advance_recv(ctx);
    return 0;
}


// MGF1 mask generation function based on SHA-256
static void mgf1_sha256(const uint8_t *seed, int seed_len, uint8_t *out, int out_len) {
    uint8_t tmp[32], counter[4] = {0, 0, 0, 0};
    int produced = 0;
    SHA256State s;
    while (produced < out_len) {
        sha256_init(&s);
        sha256_process(&s, seed, seed_len);
        sha256_process(&s, counter, 4);
        sha256_done(&s, tmp);
        int take = (out_len - produced) < 32 ? (out_len - produced) : 32;
        memcpy(out + produced, tmp, take);
        produced += take;
        for (int i = 3; i >= 0; i--) if (++counter[i] != 0) break;
    }
}


// RSASSA-PSS signature (TLS 1.3)
static int rsa_pss_sign(const RSAKey *key, const uint8_t *msg, int msg_len, uint8_t *sig, int sig_len) {
    int k = key->n_len;
    if (k != 256) return -1;
    uint8_t hash[32]; SHA256State sha; sha256_init(&sha); sha256_process(&sha, msg, msg_len); sha256_done(&sha, hash);
    int em_bits = 8 * k - 1, h_len = 32, s_len = 32, em_len = k;
    int ps_len = em_len - s_len - h_len - 2;
    uint8_t mh[72]; memset(mh, 0, 8); memcpy(mh + 8, hash, 32);
    uint8_t salt[32]; tls_random(salt, 32);
    memcpy(mh + 40, salt, 32);
    uint8_t H[32]; sha256_init(&sha); sha256_process(&sha, mh, 72); sha256_done(&sha, H);
    uint8_t db[256]; memset(db, 0, ps_len); db[ps_len] = 0x01; memcpy(db + ps_len + 1, salt, s_len);
    uint8_t db_mask[256]; mgf1_sha256(H, 32, db_mask, em_len - h_len - 1);
    uint8_t em[256];
    for (int i = 0; i < em_len - h_len - 1; i++) em[i] = db[i] ^ db_mask[i];
    em[0] &= (uint8_t)(0xFF >> (8 * em_len - em_bits));
    memcpy(em + em_len - h_len - 1, H, h_len);
    em[em_len - 1] = 0xBC;
    return rsa_private_op(key, em, k, sig, sig_len);
}


// Verify an RSASSA-PSS signature
static int rsa_pss_verify(const RSAKey *key, const uint8_t *msg, int msg_len, const uint8_t *sig, int sig_len) {
    int k = key->n_len;
    if (k != 256 || sig_len != 256) return -1;
    uint8_t hash[32]; SHA256State sha; sha256_init(&sha); sha256_process(&sha, msg, msg_len); sha256_done(&sha, hash);
    uint8_t em[256];
    if (rsa_public_op(key, sig, sig_len, em, k) != 0) return -1;
    int em_bits = 8 * k - 1, h_len = 32, s_len = 32, em_len = k;
    if (em[0] & 0x80) return -1;
    if (em[em_len - 1] != 0xBC) return -1;
    uint8_t H[32]; memcpy(H, em + em_len - h_len - 1, h_len);
    uint8_t db_mask[256]; mgf1_sha256(H, 32, db_mask, em_len - h_len - 1);
    uint8_t db[256];
    for (int i = 0; i < em_len - h_len - 1; i++) db[i] = em[i] ^ db_mask[i];
    db[0] &= (uint8_t)(0xFF >> (8 * em_len - em_bits));
    int ps_len = em_len - s_len - h_len - 2;
    for (int i = 0; i < ps_len; i++) if (db[i] != 0) return -1;
    if (db[ps_len] != 0x01) return -1;
    uint8_t salt[32]; memcpy(salt, db + ps_len + 1, s_len);
    uint8_t mh[72]; memset(mh, 0, 8); memcpy(mh + 8, hash, 32); memcpy(mh + 40, salt, 32);
    uint8_t H2[32]; sha256_init(&sha); sha256_process(&sha, mh, 72); sha256_done(&sha, H2);
    return memcmp(H, H2, 32) == 0 ? 0 : -1;
}


// Generate an ephemeral ECDH key (TLS 1.3)
static int tls13_generate_ec(TLSContext *ctx) {
    if (ctx->group == TLS_RSA_CURVE_X25519) return tls_generate_x25519_key(&ctx->local_x25519_key);
    return tls_generate_p256_key(&ctx->local_ec_key);
}


// Compute the ECDH shared secret (TLS 1.3)
static void tls13_compute_shared(TLSContext *ctx) {
    if (ctx->group == TLS_RSA_CURVE_X25519) {
        tls_x25519_shared_secret(ctx->local_x25519_key.priv, ctx->remote_x25519_pub, ctx->ecdh_shared);
        return;
    }
    ECPoint remote, result;
    memcpy(remote.x, ctx->remote_ec_ecdh_key.x, 32);
    memcpy(remote.y, ctx->remote_ec_ecdh_key.y, 32); remote.infinity = 0;
    ec_mul(&result, ctx->local_ec_key.k, &remote);
    memcpy(ctx->ecdh_shared, result.x, 32);
}


// Write the client key_share (TLS 1.3)
static void tls13_write_client_key_share(TLSContext *ctx, uint8_t *out, int *pos) {
    tls13_generate_ec(ctx);
    if (ctx->group == TLS_RSA_CURVE_X25519) {
        w16(out + *pos, TLS_RSA_CURVE_X25519); *pos += 2;
        w16(out + *pos, TLS_RSA_X25519_KEY_SIZE); *pos += 2;
        memcpy(out + *pos, ctx->local_x25519_key.pub, TLS_RSA_X25519_KEY_SIZE); *pos += TLS_RSA_X25519_KEY_SIZE;
    } else {
        w16(out + *pos, TLS_RSA_CURVE_SECP256R1); *pos += 2;
        w16(out + *pos, 65); *pos += 2;
        out[*pos] = 0x04; *pos += 1;
        memcpy(out + *pos, ctx->local_ec_key.x, 32); *pos += 32;
        memcpy(out + *pos, ctx->local_ec_key.y, 32); *pos += 32;
    }
}


// Build a TLS 1.3 ClientHello
static int tls13_build_client_hello(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x01;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS13_HS_CLIENT_HELLO;
    int hl_pos = pos; pos += 3;
    w16(out + pos, 0x0303); pos += 2;
    tls_random(ctx->client_random, 32);
    uint32_t now = (uint32_t)time(NULL); w32(ctx->client_random, now);
    memcpy(out + pos, ctx->client_random, 32); pos += 32;
    tls_random(ctx->session_id, 32); ctx->session_id_len = 32;
    out[pos++] = 32; memcpy(out + pos, ctx->session_id, 32); pos += 32;
    w16(out + pos, 2); pos += 2; w16(out + pos, TLS13_CIPHER_SUITE); pos += 2;
    out[pos++] = 1; out[pos++] = 0;
    int el_pos = pos; pos += 2;
    w16(out + pos, TLS13_EXT_SUPPORTED_VERSIONS); pos += 2; w16(out + pos, 3); pos += 2;
    out[pos++] = 2; w16(out + pos, 0x0304); pos += 2;
    w16(out + pos, TLS13_EXT_SUPPORTED_GROUPS); pos += 2; w16(out + pos, 6); pos += 2;
    w16(out + pos, 4); pos += 2;
    w16(out + pos, TLS_RSA_CURVE_X25519); pos += 2;
    w16(out + pos, TLS_RSA_CURVE_SECP256R1); pos += 2;
    w16(out + pos, TLS13_EXT_SIG_ALGS); pos += 2; w16(out + pos, 10); pos += 2;
    w16(out + pos, 8); pos += 2;
    w16(out + pos, 0x0403); pos += 2;
    w16(out + pos, 0x0503); pos += 2;
    w16(out + pos, TLS_RSA13_SIG_RSA_PSS_SHA256); pos += 2;
    w16(out + pos, TLS_RSA_SIG_RSA_SHA256); pos += 2;
    tls13_generate_ec(ctx);
    w16(out + pos, TLS13_EXT_KEY_SHARE); pos += 2;
    w16(out + pos, 6 + (ctx->group == TLS_RSA_CURVE_X25519 ? TLS_RSA_X25519_KEY_SIZE : 65)); pos += 2;
    w16(out + pos, 4 + (ctx->group == TLS_RSA_CURVE_X25519 ? TLS_RSA_X25519_KEY_SIZE : 65)); pos += 2;
    tls13_write_client_key_share(ctx, out, &pos);
    pos = client_hello_add_sni(ctx, out, pos);
    pos = tls13_client_hello_add_alpn(out, pos);
    w16(out + el_pos, pos - el_pos - 2);
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Parse a TLS 1.3 ClientHello
static int tls13_parse_client_hello(TLSContext *ctx, const uint8_t *hs, int hs_len) {
    if (hs_len < 4) return -1;
    int pos = 4;
    if (pos + 34 > hs_len) return -1;
    memcpy(ctx->client_random, hs + pos + 2, 32); pos += 34;
    if (pos >= hs_len) return -1;
    int sid_len = hs[pos++];
    if (pos + sid_len > hs_len) return -1;
    memcpy(ctx->session_id, hs + pos, sid_len); ctx->session_id_len = sid_len; pos += sid_len;
    if (pos + 2 > hs_len) return -1;
    int cs_len = r16(hs + pos); pos += 2;
    if (pos + cs_len > hs_len) return -1;
    int have_cipher = 0;
    for (int i = 0; i + 1 < cs_len; i += 2) if (r16(hs + pos + i) == TLS13_CIPHER_SUITE) have_cipher = 1;
    if (!have_cipher) return -1;
    pos += cs_len;
    if (pos >= hs_len) return -1;
    int comp_len = hs[pos++];
    if (pos + comp_len > hs_len) return -1; pos += comp_len;
    if (pos + 2 > hs_len) return -1;
    int ext_total = r16(hs + pos); pos += 2;
    int end = pos + ext_total;
    if (end > hs_len) return -1;
    int found_ver = 0, found_ks = 0;
    while (pos + 4 <= end) {
        uint16_t et = r16(hs + pos);
        int el = r16(hs + pos + 2);
        pos += 4;
        if (pos + el > end) return -1;
        if (et == TLS13_EXT_SUPPORTED_VERSIONS) {


            for (int i = 0; i + 1 < el; i++) if (r16(hs + pos + i) == 0x0304) found_ver = 1;
        } else if (et == TLS13_EXT_KEY_SHARE) {
            if (el >= 4) {
                int shares_len = r16(hs + pos);
                int sp = pos + 2, send = pos + 2 + shares_len;
                while (sp + 4 <= send) {
                    uint16_t group = r16(hs + sp);
                    int klen = r16(hs + sp + 2);
                    sp += 4;
                    if (sp + klen > send) break;
                    if (group == TLS_RSA_CURVE_X25519 && klen == TLS_RSA_X25519_KEY_SIZE) {
                        memcpy(ctx->remote_x25519_pub, hs + sp, TLS_RSA_X25519_KEY_SIZE);
                        ctx->group = TLS_RSA_CURVE_X25519;
                        found_ks = 1;
                    } else if (group == 23 && klen == 65 && hs[sp] == 0x04) {
                        memcpy(ctx->remote_ec_ecdh_key.x, hs + sp + 1, 32);
                        memcpy(ctx->remote_ec_ecdh_key.y, hs + sp + 33, 32);
                        ctx->remote_ec_ecdh_key.is_private = 0;
                        ctx->group = 23;
                        found_ks = 1;
                    }
                    sp += klen;
                }
            }
        }
        pos += el;
    }
    if (!(found_ver && found_ks)) {
        return -1;
    }
    return 0;
}


// Build a TLS 1.3 ServerHello
static int tls13_build_server_hello(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x03;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS13_HS_SERVER_HELLO;
    int hl_pos = pos; pos += 3;
    w16(out + pos, 0x0303); pos += 2;
    tls_random(ctx->server_random, 32);
    uint32_t now = (uint32_t)time(NULL); w32(ctx->server_random, now);
    memcpy(out + pos, ctx->server_random, 32); pos += 32;
    out[pos++] = (uint8_t)ctx->session_id_len;
    memcpy(out + pos, ctx->session_id, ctx->session_id_len); pos += ctx->session_id_len;
    w16(out + pos, TLS13_CIPHER_SUITE); pos += 2;
    out[pos++] = 0;
    int el_pos = pos; pos += 2;
    w16(out + pos, TLS13_EXT_SUPPORTED_VERSIONS); pos += 2; w16(out + pos, 2); pos += 2; w16(out + pos, 0x0304); pos += 2;
    w16(out + pos, TLS13_EXT_KEY_SHARE); pos += 2;
    w16(out + pos, 4 + (ctx->group == TLS_RSA_CURVE_X25519 ? TLS_RSA_X25519_KEY_SIZE : 65)); pos += 2;
    tls13_write_client_key_share(ctx, out, &pos);
    w16(out + el_pos, pos - el_pos - 2);
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Parse a TLS 1.3 ServerHello
static int tls13_parse_server_hello(TLSContext *ctx, const uint8_t *hs, int hs_len) {
    if (hs_len < 4) return -1;
    int pos = 4;
    if (pos + 2 > hs_len) return -1;
    if (r16(hs + pos) != 0x0303) return -1;
    pos += 2;
    memcpy(ctx->server_random, hs + pos, 32); pos += 32;
    if (pos >= hs_len) return -1;
    int sid_len = hs[pos++];
    if (pos + sid_len > hs_len) return -1; pos += sid_len;
    if (pos + 2 > hs_len) return -1;
    ctx->cipher_suite = r16(hs + pos); pos += 2;
    if (ctx->cipher_suite != TLS13_CIPHER_SUITE) return -1;
    pos++;
    if (pos + 2 > hs_len) return -1;
    int ext_total = r16(hs + pos); pos += 2;
    int end = pos + ext_total;
    if (end > hs_len) return -1;
    int found_ver = 0, found_ks = 0;
    while (pos + 4 <= end) {
        uint16_t et = r16(hs + pos);
        int el = r16(hs + pos + 2);
        pos += 4;
        if (pos + el > end) return -1;
        if (et == TLS13_EXT_SUPPORTED_VERSIONS) {
            if (el >= 2 && r16(hs + pos) == 0x0304) found_ver = 1;
        } else if (et == TLS13_EXT_KEY_SHARE) {
            if (el >= 4) {
                uint16_t group = r16(hs + pos);
                int klen = r16(hs + pos + 2);
                if (group == TLS_RSA_CURVE_X25519 && klen == TLS_RSA_X25519_KEY_SIZE) {
                    memcpy(ctx->remote_x25519_pub, hs + pos + 4, TLS_RSA_X25519_KEY_SIZE);
                    ctx->group = TLS_RSA_CURVE_X25519;
                    found_ks = 1;
                } else if (group == 23 && klen == 65 && hs[pos + 4] == 0x04) {
                    memcpy(ctx->remote_ec_ecdh_key.x, hs + pos + 5, 32);
                    memcpy(ctx->remote_ec_ecdh_key.y, hs + pos + 37, 32);
                    ctx->remote_ec_ecdh_key.is_private = 0;
                    ctx->group = 23;
                    found_ks = 1;
                }
            }
        }
        pos += el;
    }
    return (found_ver && found_ks) ? 0 : -1;
}


// Parse a Certificate message (TLS 1.3)
static int tls13_parse_certificate(TLSContext *ctx, const uint8_t *data, int len) {
    if (len < 8) return -1;
    int pos = 0;
    int req_ctx = data[pos++];
    if (pos + req_ctx > len) return -1;
    pos += req_ctx;
    if (pos + 3 > len) return -1;
    uint32_t list_len = ((uint32_t)data[pos] << 16) | ((uint32_t)data[pos + 1] << 8) | data[pos + 2]; pos += 3;
    if (list_len > (uint32_t)(len - pos)) return -1;
    if (pos + 3 > len) return -1;
    uint32_t cert_len = ((uint32_t)data[pos] << 16) | ((uint32_t)data[pos + 1] << 8) | data[pos + 2]; pos += 3;
    if (cert_len > (uint32_t)(len - pos)) return -1;
    if (tls_rsa_parse_public_der(&ctx->remote_rsa_key, data + pos, (int)cert_len) != 0) return -1;
    return 0;
}


// Verify the CertificateVerify message (TLS 1.3)
static int tls13_verify_certificate_verify(TLSContext *ctx, const uint8_t *data, int len) {
    if (len < 4 + 4) return -1;
    if (r16(data) != TLS_RSA13_SIG_RSA_PSS_SHA256) return -1;
    uint16_t sig_len = r16(data + 2);
    if (4 + sig_len > len) return -1;
    uint8_t content[160]; memset(content, 0, sizeof(content));
    memset(content, 0x20, 64);
    static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
    memcpy(content + 64, ctx_str, sizeof(ctx_str) - 1);
    content[64 + sizeof(ctx_str) - 1] = 0x00;
    SHA256State cp = ctx->handshake_hash; uint8_t th[32]; sha256_done(&cp, th);
    memcpy(content + 64 + sizeof(ctx_str) - 1 + 1, th, 32);
    int mlen = 64 + (int)sizeof(ctx_str) - 1 + 1 + 32;
    return rsa_pss_verify(&ctx->remote_rsa_key, content, mlen, data + 4, sig_len);
}


// Process the server flight on the client (TLS 1.3)
static int tls13_client_process_flight(TLSContext *ctx) {
    const uint8_t *data = ctx->t13_cl_flight;
    int len = ctx->t13_cl_flight_len;
    int pos = ctx->t13_cl_flight_pos;
    int seen = ctx->t13_cl_seen;

    while (pos + 4 <= len) {
        uint8_t type = data[pos];
        int mlen = ((uint32_t)data[pos + 1] << 16) | ((uint32_t)data[pos + 2] << 8) | data[pos + 3];

        if (pos + 4 + mlen > len) break;
        if (type == TLS13_HS_CERTIFICATE) {
            if (ctx->peer_verify_enabled) {
                if (tls13_parse_certificate(ctx, data + pos + 4, mlen) != 0) return -1;
            }
            seen |= 2;
        } else if (type == TLS13_HS_CERTIFICATE_VERIFY) {
            if (ctx->peer_verify_enabled) {
                if (tls13_verify_certificate_verify(ctx, data + pos + 4, mlen) != 0) return -1;
            }
            seen |= 4;
        } else if (type == TLS13_HS_FINISHED) {
            if (mlen != 32) return -1;
            SHA256State cp = ctx->handshake_hash; uint8_t th[32]; sha256_done(&cp, th);
            uint8_t exp[32]; tls13_finished_verify(ctx->s_hs_finish_key, th, exp);
            if (memcmp(data + pos + 4, exp, 32) != 0) return -1;
            seen |= 8;
        } else if (type == TLS13_HS_ENCRYPTED_EXTENSIONS) {
            seen |= 1;
        }
        sha256_process(&ctx->handshake_hash, data + pos, 4 + mlen);
        pos += 4 + mlen;
    }

    ctx->t13_cl_flight_pos = pos;
    ctx->t13_cl_seen = seen;
    return seen == 15 ? 0 : 1;
}


// Build the server flight (TLS 1.3)
static int tls13_server_build_flight(TLSContext *ctx, uint8_t *pt, int *pt_len) {
    int pos = 0;
    pt[pos++] = TLS13_HS_ENCRYPTED_EXTENSIONS;
    pt[pos++] = 0; pt[pos++] = 0; pt[pos++] = 2;
    pt[pos++] = 0; pt[pos++] = 0;
    sha256_process(&ctx->handshake_hash, pt + (pos - 6), 6);

    uint32_t cl = (uint32_t)ctx->cert_len;
    int cpos = pos;
    pt[pos++] = TLS13_HS_CERTIFICATE;
    int hl = pos; pos += 3;
    pt[pos++] = 0;
    int list_pos = pos; pos += 3;
    pt[pos++] = (uint8_t)(cl >> 16); pt[pos++] = (uint8_t)(cl >> 8); pt[pos++] = (uint8_t)(cl & 0xFF);
    memcpy(pt + pos, ctx->cert, cl); pos += (int)cl;
    pt[pos++] = 0; pt[pos++] = 0;   /* extensions for leaf entry */
    {
        int cp = 0;
        while (cp + 2 <= ctx->chain_len) {
            int il = ((int)(uint8_t)ctx->chain[cp] << 8) | (int)(uint8_t)ctx->chain[cp + 1];
            if (il <= 0 || cp + 2 + il > ctx->chain_len) break;
            uint32_t uil = (uint32_t)il;
            pt[pos++] = (uint8_t)(uil >> 16);
            pt[pos++] = (uint8_t)(uil >> 8);
            pt[pos++] = (uint8_t)(uil & 0xFF);
            memcpy(pt + pos, ctx->chain + cp + 2, (size_t)il);
            pos += il;
            pt[pos++] = 0; pt[pos++] = 0;   /* extensions for chain entry */
            cp += 2 + il;
        }
    }
    {
        uint32_t list_len = (uint32_t)(pos - list_pos - 3);
        pt[list_pos] = (uint8_t)(list_len >> 16);
        pt[list_pos + 1] = (uint8_t)(list_len >> 8);
        pt[list_pos + 2] = (uint8_t)(list_len & 0xFF);
    }
    int clen = pos - hl - 3;
    pt[hl] = (uint8_t)(clen >> 16); pt[hl + 1] = (uint8_t)(clen >> 8); pt[hl + 2] = (uint8_t)(clen & 0xFF);
    sha256_process(&ctx->handshake_hash, pt + cpos, pos - cpos);

    {
        SHA256State cp = ctx->handshake_hash; uint8_t th[32]; sha256_done(&cp, th);
        uint8_t content[160]; memset(content, 0, sizeof(content));
        memset(content, 0x20, 64);
        static const char ctx_str[] = "TLS 1.3, server CertificateVerify";
        memcpy(content + 64, ctx_str, sizeof(ctx_str) - 1);
        content[64 + sizeof(ctx_str) - 1] = 0x00;
        memcpy(content + 64 + sizeof(ctx_str) - 1 + 1, th, 32);
        int mlen = 64 + (int)sizeof(ctx_str) - 1 + 1 + 32;
        uint8_t sig[256];
        if (rsa_pss_sign(&ctx->static_rsa_key, content, mlen, sig, 256) != 0) return -1;
        int vpos = pos;
        pt[pos++] = TLS13_HS_CERTIFICATE_VERIFY;
        int hl2 = pos; pos += 3;
        w16(pt + pos, TLS_RSA13_SIG_RSA_PSS_SHA256); pos += 2;
        w16(pt + pos, 256); pos += 2;
        memcpy(pt + pos, sig, 256); pos += 256;
        int vlen = pos - hl2 - 3;
        pt[hl2] = (uint8_t)(vlen >> 16); pt[hl2 + 1] = (uint8_t)(vlen >> 8); pt[hl2 + 2] = (uint8_t)(vlen & 0xFF);
        sha256_process(&ctx->handshake_hash, pt + vpos, pos - vpos);
    }

    {
        SHA256State cp = ctx->handshake_hash; uint8_t th[32]; sha256_done(&cp, th);
        uint8_t verify[32]; tls13_finished_verify(ctx->s_hs_finish_key, th, verify);
        int fpos = pos;
        pt[pos++] = TLS13_HS_FINISHED;
        pt[pos++] = 0; pt[pos++] = 0; pt[pos++] = 32;
        memcpy(pt + pos, verify, 32); pos += 32;
        sha256_process(&ctx->handshake_hash, pt + fpos, pos - fpos);
    }
    *pt_len = pos;
    return 0;
}


// A TLS 1.3 handshake step
static int tls13_handshake_step(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len) {
    *out_len = 0;
    if (ctx->handshake_done) return TLS_RSA_OK;

    if (!ctx->is_server) {
        switch (ctx->handshake_state) {
            case 0: {
                if (tls13_build_client_hello(ctx, out, out_len) != 0) return TLS_RSA_ERROR;
                sha256_init(&ctx->handshake_hash);
                sha256_process(&ctx->handshake_hash, out + 5, *out_len - 5);
                ctx->handshake_state = 1;
                return TLS_RSA_HANDSHAKE_DONE;
            }
            case 1: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;
                uint16_t shrl = r16(in + 3);
                if (in_len < 5 + shrl) return TLS_RSA_NEED_MORE_DATA;
                if (in[5] != TLS13_HS_SERVER_HELLO) return TLS_RSA_ERROR;


                if (!ctx->t13_cl_started) {
                    ctx->t13_cl_started = 1;
                    if (tls13_parse_server_hello(ctx, in + 5, shrl) != 0) return TLS_RSA_ERROR;
                    sha256_process(&ctx->handshake_hash, in + 5, shrl);
                    tls13_compute_shared(ctx);
                    tls13_derive_handshake_keys(ctx);
                    ctx->t13_cl_off = 5 + shrl;
                }


                int rpos = ctx->t13_cl_off;
                while (rpos >= 0 && rpos + 6 <= in_len && in[rpos] == TLS_RSA_CHANGE_CIPHER &&
                       r16(in + rpos + 3) == 1)
                    rpos += 6;


                while (rpos + 5 + 16 <= in_len) {
                    uint16_t rl = r16(in + rpos + 3);
                    if (rpos + 5 + rl > in_len) break;
                    if (in[rpos] == TLS_RSA_CHANGE_CIPHER) { rpos += 5 + (int)rl; continue; }
                    uint8_t tmp[TLS_RSA_MAX_BUFFER]; int tl_len; uint8_t ti;
                    if (tls13_decrypt_record(ctx, in + rpos, in_len - rpos, tmp, &tl_len, &ti) != 0) break;
                    if ((int)ctx->t13_cl_flight_len + tl_len > (int)sizeof(ctx->t13_cl_flight)) return TLS_RSA_ERROR;
                    memcpy(ctx->t13_cl_flight + ctx->t13_cl_flight_len, tmp, (size_t)tl_len);
                    ctx->t13_cl_flight_len += tl_len;
                    rpos += 5 + (int)rl;
                }
                ctx->t13_cl_off = rpos;


                uint8_t pt[64]; int p = 0;
                int ret_flight = tls13_client_process_flight(ctx);
                if (ret_flight != 0) {
                    if (ret_flight < 0) return TLS_RSA_ERROR;
                    return TLS_RSA_NEED_MORE_DATA;
                }

                SHA256State s1 = ctx->handshake_hash; uint8_t h1[32]; sha256_done(&s1, h1);
                uint8_t verify[32]; tls13_finished_verify(ctx->c_hs_finish_key, h1, verify);
                pt[p++] = TLS13_HS_FINISHED;
                pt[p++] = 0; pt[p++] = 0; pt[p++] = 32;
                memcpy(pt + p, verify, 32); p += 32;
                sha256_process(&ctx->handshake_hash, pt, p);
                tls13_derive_application_keys(ctx, h1);
                ctx->t13_app_recv = 1;
                if (tls13_encrypt_record(ctx, TLS_RSA_HANDSHAKE, pt, p, out, out_len) != 0) return TLS_RSA_ERROR;
                ctx->t13_app_send = 1;
                ctx->handshake_state = 0;
                ctx->handshake_done = 1;


                stash_leftover(ctx, in, ctx->t13_cl_off, in_len);
                return TLS_RSA_OK;
            }
        }
        return TLS_RSA_ERROR;
    } else {
        switch (ctx->handshake_state) {
            case 0: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;
                uint16_t rec_len = r16(in + 3);
                if (in_len < 5 + rec_len) return TLS_RSA_NEED_MORE_DATA;
                if (in[5] != TLS_RSA_HS_CLIENT_HELLO) return TLS_RSA_ERROR;
                if (tls13_parse_client_hello(ctx, in + 5, rec_len) != 0) return TLS_RSA_ERROR;
                sha256_init(&ctx->handshake_hash);
                sha256_process(&ctx->handshake_hash, in + 5, rec_len);
                if (!ctx->has_cert) {
                    if (tls_rsa_generate_key(&ctx->static_rsa_key) != 0) return TLS_RSA_ERROR;
                    if (tls_generate_self_signed_cert(&ctx->static_rsa_key, ctx->cert, &ctx->cert_len) != 0) return TLS_RSA_ERROR;
                    ctx->has_cert = 1; ctx->has_rsa_key = 1;
                }
tls13_generate_ec(ctx);
                uint8_t sh_buf[512]; int sh_len;
                if (tls13_build_server_hello(ctx, sh_buf, &sh_len) != 0) return TLS_RSA_ERROR;
                sha256_process(&ctx->handshake_hash, sh_buf + 5, sh_len - 5);
                tls13_compute_shared(ctx);
                tls13_derive_handshake_keys(ctx);
                uint8_t pt[TLS_RSA_MAX_BUFFER]; int pt_len;
                if (tls13_server_build_flight(ctx, pt, &pt_len) != 0) return TLS_RSA_ERROR;
                uint8_t enc[TLS_RSA_MAX_BUFFER]; int enc_len;
                if (tls13_encrypt_record(ctx, TLS_RSA_HANDSHAKE, pt, pt_len, enc, &enc_len) != 0) return TLS_RSA_ERROR;
                memcpy(out, sh_buf, sh_len);
                memcpy(out + sh_len, enc, enc_len);
                *out_len = sh_len + enc_len;
                ctx->t13_app_send = 1;
                ctx->handshake_state = 1;
                return TLS_RSA_HANDSHAKE_DONE;
            }
            case 1: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;

                /* Skip the legacy ChangeCipherSpec record (Chrome always
                 * sends it; pure RFC 8446 clients may not). */
                int cpos = 0;
                while (in_len >= cpos + 6 && in[cpos] == TLS_RSA_CHANGE_CIPHER && r16(in + cpos + 3) == 1)
                    cpos += 6;
                if (cpos >= in_len) return TLS_RSA_NEED_MORE_DATA;

                /* The client's encrypted Flight may be fragmented across
                 * several TLS records (Chrome splits the 36-byte Finished
                 * into e.g. a 2-byte and a 34-byte fragment). Collect the
                 * decrypted fragments into a buffer. ssl.c re-feeds the same
                 * input buffer (appending newly arrived bytes) on
                 * NEED_MORE_DATA, so we resume from where the previous call
                 * stopped instead of decrypting the same record twice. */
                int start = ctx->t13_srv_off > cpos ? ctx->t13_srv_off : cpos;
                while (start + 5 <= in_len) {
                    uint16_t rl = r16(in + start + 3);
                    if (start + 5 + (int)rl > in_len) break; // partial record: wait for more
                    uint8_t dec[TLS_RSA_MAX_BUFFER]; int dec_len; uint8_t inner;
                    if (tls13_decrypt_record(ctx, in + start, in_len - start, dec, &dec_len, &inner) != 0)
                        return TLS_RSA_ERROR;
                    if ((int)ctx->t13_srv_flight_len + dec_len > (int)sizeof(ctx->t13_srv_flight_buf))
                        return TLS_RSA_ERROR;
                    memcpy(ctx->t13_srv_flight_buf + ctx->t13_srv_flight_len, dec, (size_t)dec_len);
                    ctx->t13_srv_flight_len += dec_len;
                    start += 5 + (int)rl;
                    ctx->t13_srv_off = start;
                    if (ctx->t13_srv_flight_len >= 36) break;
                }

                // Finished handshake message: type(1) + length(3) + verify_data(32)
                if (ctx->t13_srv_flight_len < 36) return TLS_RSA_NEED_MORE_DATA;

                const uint8_t *dec = ctx->t13_srv_flight_buf;
                if (dec[0] != TLS13_HS_FINISHED || dec[1] != 0 || dec[2] != 0 || dec[3] != 32)
                    return TLS_RSA_ERROR;
                SHA256State s1 = ctx->handshake_hash; uint8_t h1[32]; sha256_done(&s1, h1);
                uint8_t verify[32]; tls13_finished_verify(ctx->c_hs_finish_key, h1, verify);
                if (memcmp(dec + 4, verify, 32) != 0) return TLS_RSA_ERROR;
                sha256_process(&ctx->handshake_hash, dec, 36);
                tls13_derive_application_keys(ctx, h1);
                ctx->t13_app_recv = 1;
                stash_leftover(ctx, in, start, in_len);
                ctx->handshake_state = 0;
                ctx->handshake_done = 1;
                return TLS_RSA_OK;
            }
        }
        return TLS_RSA_ERROR;
    }
}


// Build a ClientHello with version selection (1.2/1.3)
static int build_client_hello_auto(TLSContext *ctx, uint8_t *out, int *out_len) {
    int pos = 0;
    out[pos++] = TLS_RSA_HANDSHAKE; out[pos++] = 0x03; out[pos++] = 0x01;
    int rl_pos = pos; pos += 2;
    out[pos++] = TLS13_HS_CLIENT_HELLO;
    int hl_pos = pos; pos += 3;
    w16(out + pos, 0x0303); pos += 2;
    tls_random(ctx->client_random, 32);
    uint32_t now = (uint32_t)time(NULL); w32(ctx->client_random, now);
    memcpy(out + pos, ctx->client_random, 32); pos += 32;
    tls_random(ctx->session_id, 32); ctx->session_id_len = 32;
    out[pos++] = 32; memcpy(out + pos, ctx->session_id, 32); pos += 32;

    w16(out + pos, 4); pos += 2;
    w16(out + pos, TLS13_CIPHER_SUITE); pos += 2;
    w16(out + pos, TLS_RSA_CIPHER_SUITE); pos += 2;
    out[pos++] = 1; out[pos++] = 0;
    int el_pos = pos; pos += 2;
    w16(out + pos, TLS13_EXT_SUPPORTED_VERSIONS); pos += 2; w16(out + pos, 5); pos += 2;
    out[pos++] = 4;
    w16(out + pos, 0x0304); pos += 2; w16(out + pos, 0x0303); pos += 2;
    w16(out + pos, TLS13_EXT_SUPPORTED_GROUPS); pos += 2; w16(out + pos, 6); pos += 2;
    w16(out + pos, 4); pos += 2;
    w16(out + pos, TLS_RSA_CURVE_X25519); pos += 2;
    w16(out + pos, TLS_RSA_CURVE_SECP256R1); pos += 2;
    w16(out + pos, TLS13_EXT_SIG_ALGS); pos += 2; w16(out + pos, 12); pos += 2;
    w16(out + pos, 10); pos += 2;
    w16(out + pos, 0x0403); pos += 2;
    w16(out + pos, 0x0503); pos += 2;
    w16(out + pos, TLS_RSA13_SIG_RSA_PSS_SHA256); pos += 2;
    w16(out + pos, TLS_RSA_SIG_RSA_SHA256); pos += 2;
    w16(out + pos, 0x0203); pos += 2;
    tls13_generate_ec(ctx);
    w16(out + pos, TLS13_EXT_KEY_SHARE); pos += 2;
    w16(out + pos, 6 + (ctx->group == TLS_RSA_CURVE_X25519 ? TLS_RSA_X25519_KEY_SIZE : 65)); pos += 2;
    w16(out + pos, 4 + (ctx->group == TLS_RSA_CURVE_X25519 ? TLS_RSA_X25519_KEY_SIZE : 65)); pos += 2;
    tls13_write_client_key_share(ctx, out, &pos);
    pos = client_hello_add_sni(ctx, out, pos);
    pos = tls13_client_hello_add_alpn(out, pos);
    w16(out + el_pos, pos - el_pos - 2);
    int hs_len = pos - hl_pos - 3;
    out[hl_pos] = (hs_len >> 16) & 0xFF; out[hl_pos + 1] = (hs_len >> 8) & 0xFF; out[hl_pos + 2] = hs_len & 0xFF;
    w16(out + rl_pos, pos - rl_pos - 2);
    *out_len = pos;
    return 0;
}


// Check whether a ClientHello offers TLS 1.3
static int client_hello_offers_tls13(TLSContext *ctx, const uint8_t *in, int in_len) {
    if (in_len < 5) return -1;
    int rec_len = r16(in + 3);
    if (rec_len < 4 || in_len < 5 + rec_len) return -1;
    const uint8_t *hs = in + 5;
    int pos = 4;
    if (pos + 34 > rec_len) return -1;
    pos += 2 + 32;
    if (pos >= rec_len) return -1;
    int sid_len = hs[pos++];
    if (pos + sid_len > rec_len) return -1; pos += sid_len;
    if (pos + 2 > rec_len) return -1;
    int cs_len = r16(hs + pos); pos += 2;
    if (pos + cs_len > rec_len) return -1;
    int have_cipher = 0;
    for (int i = 0; i + 1 < cs_len; i += 2) if (r16(hs + pos + i) == TLS13_CIPHER_SUITE) have_cipher = 1;
    pos += cs_len;
    if (pos >= rec_len) return -1;
    int comp_len = hs[pos++];
    if (pos + comp_len > rec_len) return -1; pos += comp_len;
    if (pos + 2 > rec_len) return -1;
    int ext_total = r16(hs + pos); pos += 2;
    int end = pos + ext_total;
    if (end > rec_len) return -1;
    if (have_cipher) {
        while (pos + 4 <= end) {
            uint16_t et = r16(hs + pos);
            int el = r16(hs + pos + 2);
            pos += 4;
            if (pos + el > end) return -1;
            if (et == TLS13_EXT_SUPPORTED_VERSIONS) {
                for (int i = 0; i + 1 < el; i++) if (r16(hs + pos + i) == 0x0304) return 1;
            }
            pos += el;
        }
        return 0;
    }

    pos = 4;
    if (pos + 34 > rec_len) return 0;
    pos += 2 + 32;
    if (pos >= rec_len) return 0;
    sid_len = hs[pos++];
    if (pos + sid_len > rec_len) return 0; pos += sid_len;
    if (pos + 2 > rec_len) return 0;
    cs_len = r16(hs + pos); pos += 2;
    if (pos + cs_len > rec_len) return 0;
    pos += cs_len;
    if (pos >= rec_len) return 0;
    comp_len = hs[pos++];
    if (pos + comp_len > rec_len) return 0; pos += comp_len;
    if (pos + 2 > rec_len) return 0;
    ext_total = r16(hs + pos); pos += 2;
    end = pos + ext_total;
    if (end > rec_len) return 0;
    while (pos + 4 <= end) {
        uint16_t et = r16(hs + pos);
        int el = r16(hs + pos + 2);
        pos += 4;
        if (pos + el > end) break;
        if (et == TLS13_EXT_KEY_SHARE && el >= 4) {
            int shares_len = r16(hs + pos);
            int sp = pos + 2, send = pos + 2 + shares_len;
            while (sp + 4 <= send) {
                uint16_t group = r16(hs + sp);
                int klen = r16(hs + sp + 2);
                sp += 4;
                if (sp + klen > send) break;
                if (group == TLS_RSA_CURVE_X25519 && klen == TLS_RSA_X25519_KEY_SIZE) {
                    if (ctx) ctx->group = TLS_RSA_CURVE_X25519;
                    break;
                } else if (group == TLS_RSA_CURVE_SECP256R1 && klen == 65) {
                    if (ctx) ctx->group = TLS_RSA_CURVE_SECP256R1;
                    break;
                }
                sp += klen;
            }
        }
        pos += el;
    }
    return 0;
}


// Check whether a ServerHello selected TLS 1.3
static int server_hello_is_tls13(const uint8_t *in, int in_len) {
    if (in_len < 5) return -1;
    uint16_t rec_len = r16(in + 3);
    if (in_len < 5 + rec_len) return -1;
    const uint8_t *hs = in + 5;
    if (hs[0] != TLS13_HS_SERVER_HELLO) return -1;
    int pos = 4;
    if (pos + 34 > rec_len) return -1;
    pos += 2 + 32;
    if (pos >= rec_len) return -1;
    int sid_len = hs[pos++];
    if (pos + sid_len > rec_len) return -1; pos += sid_len;
    if (pos + 2 > rec_len) return -1;
    uint16_t cipher = r16(hs + pos);
    return cipher == TLS13_CIPHER_SUITE ? 1 : 0;
}


// Process one TLS handshake step
int tls_handshake_step(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len) {
    *out_len = 0;
    if (ctx->handshake_done) return TLS_RSA_OK;

    if (ctx->tls13 == TLS_RSA_VERSION_AUTO) {
        if (ctx->is_server) {
            int offered = client_hello_offers_tls13(ctx, in, in_len);
            if (offered < 0) { *out_len = 0; return TLS_RSA_NEED_MORE_DATA; }
            if (offered) { ctx->tls13 = 1; ctx->cipher_suite = TLS13_CIPHER_SUITE; }
            else ctx->tls13 = 0;
        } else {
            if (ctx->handshake_state == 0) {
                build_client_hello_auto(ctx, out, out_len);
                sha256_init(&ctx->handshake_hash);
                sha256_process(&ctx->handshake_hash, out + 5, *out_len - 5);
                ctx->handshake_state = 1;
                return TLS_RSA_HANDSHAKE_DONE;
            } else {
                int v = server_hello_is_tls13(in, in_len);
                if (v < 0) { *out_len = 0; return TLS_RSA_NEED_MORE_DATA; }
                ctx->tls13 = v;
            }
        }
    }

    if (ctx->tls13) return tls13_handshake_step(ctx, in, in_len, out, out_len);

    if (!ctx->is_server) {
        switch (ctx->handshake_state) {
            case 0: {
                build_client_hello(ctx, out, out_len);
                sha256_init(&ctx->handshake_hash);
                sha256_process(&ctx->handshake_hash, out + 5, *out_len - 5);
                ctx->handshake_state = 1;
                return TLS_RSA_HANDSHAKE_DONE;
            }
            case 1: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;


                int offset = ctx->t12_cl_consumed;
                int saw_sh = ctx->t12_cl_saw_sh, saw_cert = ctx->t12_cl_saw_cert,
                    saw_ske = ctx->t12_cl_saw_ske, saw_shd = ctx->t12_cl_saw_shd;
                while (offset + 5 <= in_len) {
                    uint16_t rec_len = r16(in + offset + 3);
                    if (offset + 5 + (int)rec_len > in_len) {

                        ctx->t12_cl_consumed = offset;
                        ctx->t12_cl_saw_sh = saw_sh;
                        ctx->t12_cl_saw_cert = saw_cert;
                        ctx->t12_cl_saw_ske = saw_ske;
                        ctx->t12_cl_saw_shd = saw_shd;
                        return TLS_RSA_NEED_MORE_DATA;
                    }
                    uint8_t hs_type = in[offset + 5];
                    if (hs_type == TLS_RSA_HS_SERVER_HELLO) {
                        if (parse_server_hello(ctx, in + offset + 5, rec_len) != 0) return TLS_RSA_ERROR;
                        saw_sh = 1;
                    } else if (hs_type == TLS_RSA_HS_CERTIFICATE) {
                        if (ctx->peer_verify_enabled) {
                            if (parse_certificate(ctx, in + offset + 5, rec_len) != 0) return TLS_RSA_ERROR;
                        }
                        saw_cert = 1;
                    } else if (hs_type == TLS_RSA_HS_SERVER_KEY_EXCHANGE) {
                        if (parse_server_key_exchange(ctx, in + offset + 5, rec_len, ctx->peer_verify_enabled) != 0) return TLS_RSA_ERROR;
                        saw_ske = 1;
                    } else if (hs_type == TLS_RSA_HS_SERVER_HELLO_DONE) {
                        saw_shd = 1;
                    } else {
                        return TLS_RSA_ERROR;
                    }
                    sha256_process(&ctx->handshake_hash, in + offset + 5, rec_len);
                    offset += 5 + rec_len;
                }
                ctx->t12_cl_consumed = offset;
                ctx->t12_cl_saw_sh = saw_sh;
                ctx->t12_cl_saw_cert = saw_cert;
                ctx->t12_cl_saw_ske = saw_ske;
                ctx->t12_cl_saw_shd = saw_shd;
                if (offset != in_len) return TLS_RSA_NEED_MORE_DATA;
                if (!saw_sh || !saw_cert || !saw_ske || !saw_shd) return TLS_RSA_NEED_MORE_DATA;
                uint8_t cke_buf[256], ccs_buf[16], fin_buf[512];
                int cke_len, ccs_len, fin_len;
                build_client_key_exchange(ctx, cke_buf, &cke_len);
                sha256_process(&ctx->handshake_hash, cke_buf + 5, cke_len - 5);
                build_change_cipher_spec(ctx, ccs_buf, &ccs_len);
                derive_master_secret(ctx, ctx->ecdh_shared);
                derive_keys(ctx);
                uint8_t fin_plain[64]; int fin_plain_len = 0;
                build_finished(ctx, fin_buf, &fin_len, fin_plain, &fin_plain_len);
                sha256_process(&ctx->handshake_hash, fin_plain, fin_plain_len);
                memcpy(out, cke_buf, cke_len);
                memcpy(out + cke_len, ccs_buf, ccs_len);
                memcpy(out + cke_len + ccs_len, fin_buf, fin_len);
                *out_len = cke_len + ccs_len + fin_len;
                ctx->handshake_state = 2;
                return TLS_RSA_HANDSHAKE_DONE;
            }
            case 2: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;
                int offset = 0;
                if (in[0] == TLS_RSA_CHANGE_CIPHER) {
                    offset = 6;
                    if (in_len < offset) return TLS_RSA_NEED_MORE_DATA;
                }
                if (in_len < offset + 5) return TLS_RSA_NEED_MORE_DATA;
                if (offset > 0 && in_len >= offset + 6 && in[offset] == TLS_RSA_CHANGE_CIPHER) {
                    offset += 6;
                }
                int rec_len = r16(in + offset + 3);
                if (offset + 5 + rec_len > in_len) return TLS_RSA_NEED_MORE_DATA;
                if (rec_len < 8 + 16 || rec_len > 2048) return TLS_RSA_ERROR;
                uint8_t decrypted[2048]; int dec_len;
                int rc = decrypt_record(ctx, in + offset, 5 + rec_len, decrypted, &dec_len);
                if (rc != 0) return rc;
                if (decrypted[0] == TLS_RSA_HS_FINISHED) {
                    if (parse_finished(ctx, decrypted, dec_len) != 0) return TLS_RSA_ERROR;
                    ctx->handshake_state = 0;
                    ctx->handshake_done = 1;
                    stash_leftover(ctx, in, offset + 5 + rec_len, in_len);
                    return TLS_RSA_OK;
                }
                return TLS_RSA_ERROR;
            }
        }
    } else {
        switch (ctx->handshake_state) {
            case 0: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;
                int rec_len = r16(in + 3);
                if (in_len < 5 + rec_len) return TLS_RSA_NEED_MORE_DATA;
                if (in[5] != TLS_RSA_HS_CLIENT_HELLO) return TLS_RSA_ERROR;
                memcpy(ctx->client_random, in + 11, 32);
                ctx->client_sent_reneg = client_hello_has_extension(in + 5, rec_len, 0xFF01);
                sha256_init(&ctx->handshake_hash);
                sha256_process(&ctx->handshake_hash, in + 5, rec_len);
                if (!ctx->has_cert) {
                    if (tls_rsa_generate_key(&ctx->static_rsa_key) != 0) return TLS_RSA_ERROR;
                    if (tls_generate_self_signed_cert(&ctx->static_rsa_key, ctx->cert, &ctx->cert_len) != 0) return TLS_RSA_ERROR;
                    ctx->has_cert = 1;
                    ctx->has_rsa_key = 1;
                }
                uint8_t sh_buf[512], cert_buf[TLS_RSA_MAX_CERT_SIZE + TLS_RSA_MAX_CHAIN_SIZE + 64], ske_buf[512], shd_buf[64];
                int sh_len, cert_len, ske_len, shd_len;
                build_server_hello(ctx, sh_buf, &sh_len);
                sha256_process(&ctx->handshake_hash, sh_buf + 5, sh_len - 5);
                if (build_certificate(ctx, cert_buf, (int)sizeof(cert_buf), &cert_len) != 0) return TLS_RSA_ERROR;
                sha256_process(&ctx->handshake_hash, cert_buf + 5, cert_len - 5);
                build_server_key_exchange(ctx, ske_buf, &ske_len);
                sha256_process(&ctx->handshake_hash, ske_buf + 5, ske_len - 5);
                build_server_hello_done(ctx, shd_buf, &shd_len);
                sha256_process(&ctx->handshake_hash, shd_buf + 5, shd_len - 5);
                int total = 0;
                memcpy(out, sh_buf, sh_len); total += sh_len;
                memcpy(out + total, cert_buf, cert_len); total += cert_len;
                memcpy(out + total, ske_buf, ske_len); total += ske_len;
                memcpy(out + total, shd_buf, shd_len); total += shd_len;
                *out_len = total;
                ctx->handshake_state = 1;
                return TLS_RSA_HANDSHAKE_DONE;
            }
            case 1: {
                if (in_len < 5) return TLS_RSA_NEED_MORE_DATA;


                int offset = 0;
                while (in_len >= offset + 6 && in[offset] == TLS_RSA_CHANGE_CIPHER &&
                       r16(in + offset + 3) == 1) {
                    offset += 5 + (int)r16(in + offset + 3);
                }
                if (in_len < offset + 5) return TLS_RSA_NEED_MORE_DATA;

                if (in[offset] == TLS_RSA_APPLICATION_DATA) {

                    uint16_t app_rec_len = r16(in + offset + 3);
                    if (in_len < offset + 5 + (int)app_rec_len) return TLS_RSA_NEED_MORE_DATA;
                    uint8_t decrypted[8192]; int dec_len;
                    int rc = decrypt_record(ctx, in + offset, 5 + (int)app_rec_len, decrypted, &dec_len);
                    if (rc != 0) return TLS_RSA_ERROR;

                    if (dec_len >= 5 && decrypted[0] >= 0x14 && decrypted[0] <= 0x17) {
                        uint16_t inner_rec_len = r16(decrypted + 3);
                        if (dec_len >= 5 + (int)inner_rec_len) {
                            uint8_t inner_decrypted[8192]; int inner_dec_len;
                            int inner_rc = decrypt_record(ctx, decrypted, 5 + (int)inner_rec_len, inner_decrypted, &inner_dec_len);
                            if (inner_rc == 0 && inner_dec_len > 0) {

                                if (inner_dec_len >= 4 && (memcmp(inner_decrypted, "GET ", 4) == 0 ||
                                    memcmp(inner_decrypted, "POST ", 5) == 0 ||
                                    memcmp(inner_decrypted, "HEAD ", 5) == 0 ||
                                    memcmp(inner_decrypted, "PUT ", 4) == 0 ||
                                    memcmp(inner_decrypted, "DELETE ", 7) == 0 ||
                                    memcmp(inner_decrypted, "OPTIONS ", 8) == 0)) {
                                    if (inner_dec_len < (int)sizeof(ctx->recv_buffer.data)) {
                                        memcpy(ctx->recv_buffer.data, inner_decrypted, (size_t)inner_dec_len);
                                        ctx->recv_buffer.len = (uint32_t)inner_dec_len;
                                    }
                                    ctx->handshake_done = 1;
                                    stash_leftover(ctx, in, offset + 5 + (int)app_rec_len, in_len);
                                    return TLS_RSA_OK;
                                }
                            }
                        }
                    }

                    if (dec_len < 4 || memcmp(decrypted, "GET ", 4) != 0 &&
                        memcmp(decrypted, "POST ", 5) != 0 &&
                        memcmp(decrypted, "HEAD ", 5) != 0 &&
                        memcmp(decrypted, "PUT ", 4) != 0 &&
                        memcmp(decrypted, "DELETE ", 7) != 0 &&
                        memcmp(decrypted, "OPTIONS ", 8) != 0) {
                        return TLS_RSA_ERROR;
                    }

                    if (dec_len > 0 && dec_len < (int)sizeof(ctx->recv_buffer.data)) {
                        memcpy(ctx->recv_buffer.data, decrypted, (size_t)dec_len);
                        ctx->recv_buffer.len = (uint32_t)dec_len;
                    }

                    ctx->handshake_done = 1;
                    stash_leftover(ctx, in, offset + 5 + (int)app_rec_len, in_len);
                    return TLS_RSA_OK;
                }

                int ckex_rec_len = r16(in + offset + 3);
                if (in_len < offset + 5 + ckex_rec_len) return TLS_RSA_NEED_MORE_DATA;
                if (in[offset + 5] != TLS_RSA_HS_CLIENT_KEY_EXCHANGE) { return TLS_RSA_ERROR; }
                parse_client_key_exchange(ctx, in + offset + 5, ckex_rec_len);
                sha256_process(&ctx->handshake_hash, in + offset + 5, ckex_rec_len);

                if (ctx->group == TLS_RSA_CURVE_X25519) {
                    if (!ctx->local_x25519_key.is_private) {
                        tls_generate_x25519_key(&ctx->local_x25519_key);
                    }
                    tls_x25519_shared_secret(ctx->local_x25519_key.priv, ctx->remote_x25519_pub, ctx->ecdh_shared);
                } else {
                    if (!ctx->local_ec_key.is_private) {
                        tls_generate_p256_key(&ctx->local_ec_key);
                    }
                    ECPoint remote, result;
                    memcpy(remote.x, ctx->remote_ec_ecdh_key.x, 32);
                    memcpy(remote.y, ctx->remote_ec_ecdh_key.y, 32); remote.infinity = 0;
                    ec_mul(&result, ctx->local_ec_key.k, &remote);
                    memcpy(ctx->ecdh_shared, result.x, 32);
                }
                derive_master_secret(ctx, ctx->ecdh_shared);
                derive_keys(ctx);
                int ccs_offset = offset + 5 + ckex_rec_len;
                if (in_len < ccs_offset + 6) return TLS_RSA_NEED_MORE_DATA;
                if (in[ccs_offset] != TLS_RSA_CHANGE_CIPHER) return TLS_RSA_ERROR;
                ccs_offset += 6;
                if (in_len < ccs_offset + 5) return TLS_RSA_NEED_MORE_DATA;
                uint8_t decrypted[512]; int dec_len;
                int rc = decrypt_record(ctx, in + ccs_offset, in_len - ccs_offset, decrypted, &dec_len);
                if (rc != 0) return rc;
                if (decrypted[0] != TLS_RSA_HS_FINISHED) return TLS_RSA_ERROR;
                if (parse_finished(ctx, decrypted, dec_len) != 0) return TLS_RSA_ERROR;
                sha256_process(&ctx->handshake_hash, decrypted, dec_len);
                uint8_t ccs_buf[16], fin_buf[512];
                int ccs_len, fin_len;
                build_change_cipher_spec(ctx, ccs_buf, &ccs_len);
                build_finished(ctx, fin_buf, &fin_len, NULL, NULL);
                memcpy(out, ccs_buf, ccs_len);
                memcpy(out + ccs_len, fin_buf, fin_len);
                *out_len = ccs_len + fin_len;
                stash_leftover(ctx, in, ccs_offset + 5 + (int)r16(in + ccs_offset + 3), in_len);
                ctx->handshake_state = 0;
                ctx->handshake_done = 1;
                return TLS_RSA_OK;
            }
        }
    }
    return TLS_RSA_ERROR;
}


// Encrypt and send application data
int tls_send_application_data(TLSContext *ctx, const uint8_t *data, int len, uint8_t *out, int *out_len) {
    if (!ctx->handshake_done) return TLS_RSA_ERROR;
    if (ctx->tls13) return tls13_encrypt_record(ctx, TLS_RSA_APPLICATION_DATA, data, len, out, out_len);
    return encrypt_record(ctx, TLS_RSA_APPLICATION_DATA, data, len, out, out_len);
}


// Decrypt and receive application data
int tls_receive_application_data(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *data, int *data_len) {
    if (!ctx->handshake_done) return TLS_RSA_ERROR;


    if (ctx->recv_raw.len == 0 && (!in || in_len <= 0)) return TLS_RSA_NEED_MORE_DATA;


    uint8_t combined[TLS_RSA_MAX_BUFFER + 0x10000];
    int n = 0;
    if (ctx->recv_raw.len) {
        memcpy(combined, ctx->recv_raw.data, ctx->recv_raw.len);
        n = (int)ctx->recv_raw.len;
        ctx->recv_raw.len = 0;
    }
    if (in && in_len > 0) { memcpy(combined + n, in, (size_t)in_len); n += in_len; }


    if (ctx->tls13) {


        int off = 0;
        int rc = TLS_RSA_NEED_MORE_DATA;
        int consumed = 0;
        while (off + 5 + 16 <= n) {
            uint16_t rl = r16(combined + off + 3);
            if (off + 5 + rl > n) break;
            uint8_t tmp[TLS_RSA_MAX_BUFFER]; int tl; uint8_t inner;
            if (tls13_decrypt_record(ctx, combined + off, n - off, tmp, &tl, &inner) != 0) break;
            off += 5 + (int)rl;

            if (inner == TLS_RSA_ALERT) { rc = TLS_RSA_CLOSED; consumed = off; break; }
            if (inner == TLS_RSA_APPLICATION_DATA) {
                memcpy(data, tmp, (size_t)tl); *data_len = tl;
                rc = TLS_RSA_OK; consumed = off; break;
            }
        }
        if (consumed == 0) consumed = off;
        if (rc == TLS_RSA_NEED_MORE_DATA) {

            int left = n - consumed;
            if (left > 0) {
                if (left > (int)sizeof(ctx->recv_raw.data)) left = (int)sizeof(ctx->recv_raw.data);
                memcpy(ctx->recv_raw.data, combined + consumed, (size_t)left);
                ctx->recv_raw.len = (uint32_t)left;
            }
            return rc;
        }

        if (consumed > 0 && consumed < n) {
            int left = n - consumed;
            if (left > (int)sizeof(ctx->recv_raw.data)) left = (int)sizeof(ctx->recv_raw.data);
            memcpy(ctx->recv_raw.data, combined + consumed, (size_t)left);
            ctx->recv_raw.len = (uint32_t)left;
        }
        return rc;
    }


    if (n >= 5 && combined[0] == TLS_RSA_ALERT) {
        return TLS_RSA_CLOSED;
    }
    if (n < 5) {
        memcpy(ctx->recv_raw.data, combined, (size_t)n);
        ctx->recv_raw.len = (uint32_t)n;
        return TLS_RSA_NEED_MORE_DATA;
    }
    uint16_t rlen = r16(combined + 3);
    if (n < 5 + (int)rlen) {
        if ((size_t)n > sizeof(ctx->recv_raw.data)) {
            ctx->recv_raw.len = 0;
            return TLS_RSA_ERROR;
        }
        memcpy(ctx->recv_raw.data, combined, (size_t)n);
        ctx->recv_raw.len = (uint32_t)n;
        return TLS_RSA_NEED_MORE_DATA;
    }
    int rc = decrypt_record(ctx, combined, n, data, data_len);
    if (rc != 0) {
        if ((size_t)n > sizeof(ctx->recv_raw.data)) {
            ctx->recv_raw.len = 0;
            return rc;
        }
        memcpy(ctx->recv_raw.data, combined, (size_t)n);
        ctx->recv_raw.len = (uint32_t)n;
        return rc;
    }
    int consumed = 5 + (int)rlen;

    if (consumed > 0 && consumed < n) {
        int left = n - consumed;
        if (left > (int)sizeof(ctx->recv_raw.data)) left = (int)sizeof(ctx->recv_raw.data);
        memcpy(ctx->recv_raw.data, combined + consumed, (size_t)left);
        ctx->recv_raw.len = (uint32_t)left;
    }
    return 0;
}


// Send a close_notify alert and close the connection
int tls_close(TLSContext *ctx, uint8_t *out, int *out_len) {
    uint8_t alert[2] = { 0x01, 0x00 };
    if (ctx->tls13) {
        return tls13_encrypt_record(ctx, TLS_RSA_ALERT, alert, sizeof(alert), out, out_len);
    }
    out[0] = TLS_RSA_ALERT; out[1] = 0x03; out[2] = 0x03;
    out[3] = 0; out[4] = 2; out[5] = alert[0]; out[6] = alert[1];
    *out_len = 7;
    return TLS_RSA_OK;
}

