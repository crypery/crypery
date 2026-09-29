/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * tls.h - header file of the pure C TLS/RSA library.
 *
 * Public API: TLS 1.2/1.3 context (handshake, data encryption),
 * generation and parsing of RSA/X25519/P-256 keys, AES-GCM, SHA-256,
 * HMAC-SHA256 and generation of self-signed X.509 certificates.
 */

#ifndef TLS_H
#define TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define TLS_VERSION_AUTO             0
#define TLS_VERSION_12               1
#define TLS_VERSION_13               2

#define TLS_RSA_OK                    0
#define TLS_RSA_ERROR                -1
#define TLS_RSA_NEED_MORE_DATA        1
#define TLS_RSA_HANDSHAKE_DONE        2
#define TLS_RSA_CLOSED                3

#define TLS_RSA_AES_BLOCK_SIZE       16
#define TLS_RSA_GCM_TAG_LEN          16
#define TLS_RSA_GCM_IV_LEN           4
#define TLS_RSA_GCM_EXPLICIT_LEN     8
#define TLS_RSA_SHA256_SIZE          32
#define TLS_RSA_P256_KEY_SIZE        32
#define TLS_RSA_P256_POINT_LEN       65
#define TLS_RSA_MAX_KEY_BYTES        256
#define TLS_RSA_MASTER_SIZE          48
#define TLS_RSA_RANDOM_SIZE          32
#define TLS_RSA_MAX_BUFFER           0x4000
#define TLS_RSA_MAX_CERT_SIZE        4096
#define TLS_RSA_MAX_CHAIN_SIZE       8192
#define TLS_RSA_MAX_EXTENSIONS       512

#define TLS_RSA_MODULUS_BYTES        256
#define TLS_RSA_SIGNATURE_LEN        TLS_RSA_MODULUS_BYTES
#define TLS_RSA_DIGEST_INFO_SHA256   51

#define TLS_RSA_VERSION_12           0x0303
#define TLS_RSA_VERSION_AUTO         (-1)
#define TLS_RSA_CHANGE_CIPHER        0x14
#define TLS_RSA_ALERT                0x15
#define TLS_RSA_HANDSHAKE            0x16
#define TLS_RSA_APPLICATION_DATA     0x17


#define TLS13_VERSION                0x0304
#define TLS13_CIPHER_SUITE           0x1301
#define TLS_RSA13_SIG_RSA_PSS_SHA256 0x0804
#define TLS13_HS_CLIENT_HELLO        1
#define TLS13_HS_SERVER_HELLO        2
#define TLS13_HS_ENCRYPTED_EXTENSIONS 8
#define TLS13_HS_CERTIFICATE         11
#define TLS13_HS_CERTIFICATE_VERIFY  15
#define TLS13_HS_FINISHED            20
#define TLS13_EXT_SUPPORTED_VERSIONS 0x002B
#define TLS13_EXT_SUPPORTED_GROUPS   0x000A
#define TLS13_EXT_SIG_ALGS           0x000D
#define TLS13_EXT_KEY_SHARE          0x0033

#define TLS_RSA_HS_CLIENT_HELLO       1
#define TLS_RSA_HS_SERVER_HELLO       2
#define TLS_RSA_HS_CERTIFICATE        11
#define TLS_RSA_HS_SERVER_KEY_EXCHANGE 12
#define TLS_RSA_HS_SERVER_HELLO_DONE  14
#define TLS_RSA_HS_CLIENT_KEY_EXCHANGE 16
#define TLS_RSA_HS_FINISHED           20

#define TLS_RSA_CURVE_SECP256R1      23
#define TLS_RSA_CURVE_X25519         29
#define TLS_RSA_X25519_KEY_SIZE      32

#define TLS_RSA_CIPHER_SUITE          0xC02F
#define TLS_RSA_SIG_RSA_SHA256        0x0401
#define TLS_RSA_PKCS1_RSA_ENCRYPTION  0x00

typedef struct {
    uint8_t key[TLS_RSA_AES_BLOCK_SIZE];
    uint32_t rounds;
    uint32_t rk[60];
} AESKey;

typedef struct {
    uint8_t H[16];
    uint8_t X[16];
    uint8_t Y[16];
    uint8_t Y_0[16];
    uint8_t buf[16];
    int cipher;
    int ivmode;
    int mode;
    int buflen;
    uint64_t totlen;
    uint64_t pttotlen;
    AESKey K;
} GCMState;

typedef struct {
    uint32_t state[8];
    uint32_t curlen;
    uint64_t length;
    uint8_t buf[64];
} SHA256State;

typedef struct {
    SHA256State sha;
    SHA256State hashstate;
    int hash;
    uint8_t key[64];
} HMACState;


typedef struct {
    uint8_t x[32];
    uint8_t y[32];
    uint8_t k[32];
    int is_private;
    int curve;
} ECKey;


typedef struct {
    uint8_t priv[TLS_RSA_X25519_KEY_SIZE];
    uint8_t pub[TLS_RSA_X25519_KEY_SIZE];
    int is_private;
} X25519Key;


typedef struct {
    uint8_t n[TLS_RSA_MODULUS_BYTES];
    uint8_t e[8];
    int     e_len;
    uint8_t d[TLS_RSA_MODULUS_BYTES];
    int     is_private;
    int     n_len;
    uint8_t p[TLS_RSA_MODULUS_BYTES / 2];
    uint8_t q[TLS_RSA_MODULUS_BYTES / 2];
    uint8_t dmp1[TLS_RSA_MODULUS_BYTES / 2];
    uint8_t dmq1[TLS_RSA_MODULUS_BYTES / 2];
    uint8_t iqmp[TLS_RSA_MODULUS_BYTES / 2];
} RSAKey;

typedef struct {
    int socket_fd;
    int fd_set;          // 1 after socket binding
    int rw_error;
    int closed;          // 1 after transport close/abort by peer
    uint8_t prebuf[TLS_RSA_MAX_BUFFER];
    int prebuf_len;
} SSLInternal;

typedef struct {
    uint8_t data[TLS_RSA_MAX_BUFFER];
    uint32_t len;
    uint32_t pos;
} TLSBuffer;

/* Partial-record reassembly buffer: must hold a full TLS record (up to
 * 2^14 + 256 + tag + header) plus one socket read chunk, so a split record
 * never overflows into the adjacent TLSContext fields. */
typedef struct {
    uint8_t data[TLS_RSA_MAX_BUFFER * 2];
    uint32_t len;
    uint32_t pos;
} TLSRecvRawBuffer;

typedef struct TLSContext {
    uint8_t client_random[TLS_RSA_RANDOM_SIZE];
    uint8_t server_random[TLS_RSA_RANDOM_SIZE];
    uint8_t master_secret[TLS_RSA_MASTER_SIZE];
    uint8_t key_block[TLS_RSA_MAX_KEY_BYTES];
    uint8_t client_write_key[TLS_RSA_AES_BLOCK_SIZE];
    uint8_t server_write_key[TLS_RSA_AES_BLOCK_SIZE];
    uint8_t client_write_iv[TLS_RSA_GCM_IV_LEN];
    uint8_t server_write_iv[TLS_RSA_GCM_IV_LEN];
    int is_server;
    int handshake_done;
    int cipher_suite;
    uint64_t client_sequence;
    uint64_t server_sequence;
    ECKey local_ec_key;
    ECKey remote_ec_ecdh_key;
    X25519Key local_x25519_key;
    uint8_t remote_x25519_pub[TLS_RSA_X25519_KEY_SIZE];
    int group;
    uint8_t ecdh_shared[32];
    GCMState client_gcm;
    GCMState server_gcm;
    int gcm_created;
    TLSBuffer send_buffer;
    TLSBuffer recv_buffer;
    SHA256State handshake_hash;
    int handshake_hash_created;
    uint8_t session_id[32];
    int session_id_len;
    uint8_t alert_level;
    uint8_t alert_code;
    int handshake_state;
    RSAKey static_rsa_key;
    RSAKey remote_rsa_key;
    int has_rsa_key;
    uint8_t cert[TLS_RSA_MAX_CERT_SIZE];
    int cert_len;
    int has_cert;
    /* DER-concatenated intermediate certificates (without length prefixes).
     * Stored as: [2-byte len][DER]... so build_certificate can send the
     * full chain (leaf + intermediates). Empty when only a leaf is loaded. */
    uint8_t chain[TLS_RSA_MAX_CHAIN_SIZE];
    int chain_len;
    int client_sent_reneg;

    int tls13;
    uint8_t t13_hs_secret[32];
    uint8_t c_hs_key[16], c_hs_iv[12];
    uint8_t s_hs_key[16], s_hs_iv[12];
    uint8_t c_ap_key[16], c_ap_iv[12];
    uint8_t s_ap_key[16], s_ap_iv[12];
    uint8_t c_hs_finish_key[32], s_hs_finish_key[32];
    uint64_t t13_send_seq, t13_recv_seq;
    uint64_t t13_app_send_seq, t13_app_recv_seq;
    int t13_app_send, t13_app_recv;
    char server_name[256];
    int server_name_len;


    int t13_cl_started;
    int t13_cl_off;
    uint8_t t13_cl_flight[TLS_RSA_MAX_BUFFER];
    int t13_cl_flight_len;
    int t13_cl_flight_pos;
    int t13_cl_seen;


    int t13_srv_off;
    uint8_t t13_srv_flight_buf[TLS_RSA_MAX_BUFFER];
    int t13_srv_flight_len;


    int t12_cl_consumed;
    int t12_cl_saw_sh;
    int t12_cl_saw_cert;
    int t12_cl_saw_ske;
    int t12_cl_saw_shd;
    int peer_verify_enabled;
    TLSRecvRawBuffer recv_raw;
    SSLInternal io;
    int io_timeout;        // per-socket I/O operation timeout (ms; 0 = none)
    int handshake_timeout; // summary handshake limit (ms; 0 = none)
    int read_poll;         // short wait inside write (ms)
    int flight_timeout;    // limit for assembling fragmented packets (ms; 0 = none)
} TLSContext;


// Enable or disable peer certificate verification
int tls_set_peer_verify(TLSContext *ctx, int enable);

// Initialize a TLS context for a given version
int tls_init_context(TLSContext *ctx, int is_server, int version);

// Initialize a TLS 1.3 context
int tls_init_context_13(TLSContext *ctx, int is_server);

// Initialize a TLS context with automatic version selection
int tls_init_context_auto(TLSContext *ctx, int is_server);

// Report the negotiated TLS version (1.3 or 1.2)
int tls_negotiated_tls13(const TLSContext *ctx);

// Process one TLS handshake step
int tls_handshake_step(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *out, int *out_len);

// Encrypt and send application data
int tls_send_application_data(TLSContext *ctx, const uint8_t *data, int len, uint8_t *out, int *out_len);

// Decrypt and receive application data
int tls_receive_application_data(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *data, int *data_len);

// Send a close_notify alert and close the connection
int tls_close(TLSContext *ctx, uint8_t *out, int *out_len);

// Check whether the handshake has finished
int tls_is_established(TLSContext *ctx);

// Decrypt a single TLS record
int decrypt_record(TLSContext *ctx, const uint8_t *in, int in_len, uint8_t *pt, int *pt_len);


// Set the server RSA key in the context
int tls_set_rsa_key(TLSContext *ctx, const RSAKey *key);

// Set the server certificate in the context
int tls_set_certificate(TLSContext *ctx, const uint8_t *cert, int cert_len);

// Set intermediate chain (concatenated as [u16 len][DER]...). Replaces old chain.
int tls_set_chain(TLSContext *ctx, const uint8_t *chain, int chain_len);

// Read a PEM file and decode it into DER
int tls_pem_to_der(const char *path, uint8_t *out, int *out_len, int max_out);

// Read a PEM file with a leaf + chain: first CERTIFICATE -> leaf,
// remaining CERTIFICATE blocks -> chain ([u16 len][DER]...).
int tls_pem_to_chain_der(const char *path,
                         uint8_t *leaf, int *leaf_len, int leaf_max,
                         uint8_t *chain, int *chain_len, int chain_max);


// Parse a private RSA key (PKCS#8/PKCS#1) from DER
int tls_rsa_parse_private_der(RSAKey *key, const uint8_t *der, int der_len);


// Extract the public RSA key from a DER certificate
int tls_rsa_parse_public_der(RSAKey *key, const uint8_t *der, int der_len);


// Generate a P-256 (ECDH) key pair
int tls_generate_p256_key(ECKey *key);

// Generate an X25519 key pair
int tls_generate_x25519_key(X25519Key *key);

// Compute an X25519 shared secret
int tls_x25519_shared_secret(const uint8_t *priv, const uint8_t *peer_pub, uint8_t *shared);

// Generate an RSA key pair (2048 bits)
int tls_rsa_generate_key(RSAKey *key);


typedef struct {
    char country[8];
    char state[64];
    char locality[64];
    char org[64];
    char org_unit[64];
    char common_name[256];
    int days;
} CertSubject;


// Generate a self-signed X.509 certificate (default subject)
int tls_generate_self_signed_cert(RSAKey *key, uint8_t *cert, int *cert_len);


// Generate a self-signed X.509 certificate with a custom subject
int tls_generate_self_signed_cert_ex(RSAKey *key, const CertSubject *subject, uint8_t *cert, int *cert_len);

// Sign a SHA-256 hash (RSA PKCS#1 v1.5)
int tls_rsa_sign(const RSAKey *key, const uint8_t *hash, uint8_t *sig, int *sig_len);

// Verify an RSA PKCS#1 v1.5 signature
int tls_rsa_verify(const RSAKey *pub_key, const uint8_t *hash, const uint8_t *sig, int sig_len);


// Set the server name for SNI
int tls_set_server_name(TLSContext *ctx, const char *name, int name_len);


// Initialize the AES-128 key and round keys
int aes_init_key(AESKey *key, const uint8_t *data);

// Encrypt a single 16-byte AES-128 block
int aes_encrypt_block(const AESKey *key, const uint8_t *in, uint8_t *out);

// Initialize an AES-GCM context
int gcm_init(GCMState *gcm, const uint8_t *key, int key_len);

// Reset the GCM state for a new message
int gcm_reset(GCMState *gcm);

// Set the GCM initialization vector
int gcm_add_iv(GCMState *gcm, const uint8_t *IV, int IVlen);

// Add extra authenticated data (AAD)
int gcm_add_aad(GCMState *gcm, const uint8_t *adata, int adatalen);

// Encrypt or decrypt data in GCM mode
int gcm_process(GCMState *gcm, uint8_t *pt, uint8_t *ct, int len, int direction);

// Finish GCM and compute the authentication tag
int gcm_done(GCMState *gcm, uint8_t *tag, int *taglen);

// Initialize a SHA-256 context
int sha256_init(SHA256State *md);

// Process input data for SHA-256
int sha256_process(SHA256State *md, const uint8_t *in, int inlen);

// Finish SHA-256 and output the digest
int sha256_done(SHA256State *md, uint8_t *out);

// Initialize HMAC-SHA256 with a key
int hmac_sha256_init(HMACState *hmac, const uint8_t *key, int keylen);

// Process data for HMAC-SHA256
int hmac_sha256_process(HMACState *hmac, const uint8_t *in, int inlen);

// Finish HMAC-SHA256 and output the MAC
int hmac_sha256_done(HMACState *hmac, uint8_t *out, int *outlen);

#ifdef __cplusplus
}
#endif

#endif
