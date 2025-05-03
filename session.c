// session.c
#include "session.h"
#include "dh.h"
#include "util.h"
#include "keys.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>

#ifdef __APPLE__
  #include <libkern/OSByteOrder.h>
  #define htobe64(x) OSSwapHostToBigInt64(x)
  #define be64toh(x) OSSwapBigToHostInt64(x)
#else
  #include <endian.h>
#endif

#define AES_KEYLEN   32
#define HMAC_KEYLEN  32
#define IV_LEN       16
#define HMAC_LEN     32

struct Session {
    int            sockfd;
    unsigned char  enc_key[AES_KEYLEN],
                   mac_key[HMAC_KEYLEN];
    EVP_CIPHER_CTX *enc_ctx, *dec_ctx;
    uint64_t       send_seq, recv_seq;
};

Session* session_create(int sockfd,
                        const char* my_privkey_file,
                        const char* peer_pubkey_file)
{
    Session *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->sockfd = sockfd;

    // 1) Load static DH keys
    dhKey skA, pkB;
    initKey(&skA); initKey(&pkB);
    if (readDH((char*)my_privkey_file, &skA) != 0 ||
        readDH((char*)peer_pubkey_file, &pkB) != 0) {
        free(s);
        return NULL;
    }

    // 2) Ephemeral DH
    dhKey skX, pkY;
    initKey(&skX); initKey(&pkY);
    dhGenk(&skX);

    // send X.pub, receive Y.pub
    serialize_mpz(s->sockfd, skX.PK);
    deserialize_mpz(pkY.PK,    s->sockfd);

    // 3DH → 64-byte shared secret
    unsigned char shared[64];
    dh3Finalk(&skA, &skX, &pkB, &pkY, shared, sizeof(shared));

    // derive keys
    memcpy(s->enc_key, shared,         AES_KEYLEN);
    memcpy(s->mac_key, shared + AES_KEYLEN, HMAC_KEYLEN);

    // prepare contexts (IV set per-message)
    s->enc_ctx = EVP_CIPHER_CTX_new();
    s->dec_ctx = EVP_CIPHER_CTX_new();

    s->send_seq = 1;  // start at 1
    s->recv_seq = 0;

    // wipe DH data
    shredKey(&skA); shredKey(&pkB);
    shredKey(&skX); shredKey(&pkY);

    return s;
}

int session_send(Session* s,
                 const unsigned char* pt, size_t ptlen)
{
    // 1) Sequence number
    uint64_t seq = s->send_seq++;
    uint64_t seq_be = htobe64(seq);

    // 2) Build plaintext = seq||pt
    size_t  blob_len = sizeof(seq_be) + ptlen;
    unsigned char *blob = malloc(blob_len);
    memcpy(blob, &seq_be, sizeof(seq_be));
    memcpy(blob + sizeof(seq_be), pt, ptlen);

    // 3) Generate random IV
    unsigned char iv[IV_LEN];
    if (!RAND_bytes(iv, IV_LEN)) {
        free(blob);
        return -1;
    }

    // 4) Encrypt with AES-CTR
    if (!EVP_EncryptInit_ex(s->enc_ctx, EVP_aes_256_ctr(), NULL,
                            s->enc_key, iv)) {
        free(blob);
        return -1;
    }
    int ctlen = 0;
    unsigned char *ct = malloc(blob_len);
    EVP_EncryptUpdate(s->enc_ctx, ct, &ctlen, blob, blob_len);

    // 5) HMAC-SHA256 over IV || ciphertext
    unsigned char mac[HMAC_LEN];
    unsigned int maclen;
    HMAC(EVP_sha256(), s->mac_key, HMAC_KEYLEN,
         iv, IV_LEN,            // start with IV
         mac, &maclen);

    HMAC(EVP_sha256(), s->mac_key, HMAC_KEYLEN,
         ct, ctlen,            // then ciphertext
         mac, &maclen);

    // 6) Send: [ctlen:uint32][IV][ct][MAC]
    uint32_t net_ctlen = htonl(ctlen);
    xwrite(s->sockfd, &net_ctlen, sizeof(net_ctlen));
    xwrite(s->sockfd, iv,        IV_LEN);
    xwrite(s->sockfd, ct,        ctlen);
    xwrite(s->sockfd, mac,       maclen);

    free(blob);
    free(ct);
    return 0;
}

int session_recv(Session* s,
                 unsigned char** out, size_t* outlen)
{
    // 1) Read lengths + IV + CT + MAC
    uint32_t net_ctlen;
    xread(s->sockfd, &net_ctlen, sizeof(net_ctlen));
    uint32_t ctlen = ntohl(net_ctlen);

    unsigned char iv[IV_LEN];
    xread(s->sockfd, iv, IV_LEN);

    unsigned char *ct = malloc(ctlen);
    xread(s->sockfd, ct, ctlen);

    unsigned char mac[HMAC_LEN];
    xread(s->sockfd, mac, HMAC_LEN);

    // 2) Verify HMAC
    unsigned char calc[HMAC_LEN];
    unsigned int calclen;
    HMAC(EVP_sha256(), s->mac_key, HMAC_KEYLEN,
         iv, IV_LEN,       // IV
         calc, &calclen);
    HMAC(EVP_sha256(), s->mac_key, HMAC_KEYLEN,
         ct, ctlen,        // ciphertext
         calc, &calclen);

    if (calclen != HMAC_LEN || memcmp(calc, mac, HMAC_LEN)) {
        free(ct);
        return -1;
    }

    // 3) Decrypt
    if (!EVP_DecryptInit_ex(s->dec_ctx, EVP_aes_256_ctr(), NULL,
                            s->enc_key, iv)) {
        free(ct);
        return -1;
    }
    int blob_len = 0;
    unsigned char *blob = malloc(ctlen);
    EVP_DecryptUpdate(s->dec_ctx, blob, &blob_len, ct, ctlen);

    // 4) Extract & check sequence
    uint64_t seq_be;
    memcpy(&seq_be, blob, sizeof(seq_be));
    uint64_t seq = be64toh(seq_be);
    if (seq <= s->recv_seq) {
        free(ct);
        free(blob);
        return -1;  // replay or out-of-order
    }
    s->recv_seq = seq;

    // 5) Return plaintext portion
    *outlen = blob_len - sizeof(seq_be);
    *out   = malloc(*outlen);
    memcpy(*out, blob + sizeof(seq_be), *outlen);

    free(ct);
    free(blob);
    return 0;
}

void session_destroy(Session* s) {
    OPENSSL_cleanse(s->enc_key, AES_KEYLEN);
    OPENSSL_cleanse(s->mac_key, HMAC_KEYLEN);
    EVP_CIPHER_CTX_free(s->enc_ctx);
    EVP_CIPHER_CTX_free(s->dec_ctx);
    free(s);
}
