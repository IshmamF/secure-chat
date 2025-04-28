#include "session.h"

#include "dh.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef __APPLE__
  #include <libkern/OSByteOrder.h>
  #define htobe64(x) OSSwapHostToBigInt64(x)
  #define be64toh(x) OSSwapLittleToHostInt64(x)
#else
  #include <endian.h>
#endif

struct Session {
    int sockfd;
    unsigned char enc_key[32], mac_key[32];
    EVP_CIPHER_CTX *enc_ctx, *dec_ctx;
    uint64_t send_seq, recv_seq;
};

Session* session_create(int sockfd,
                        const char* my_privkey_file,
                        const char* peer_pubkey_file) {
    // Simple ephemeral DH handshake (long-term keys not shown here)
    Session* s = malloc(sizeof(*s));
    s->sockfd = sockfd;
    // Generate ephemeral key pair
    NEWZ(sk); NEWZ(pk); NEWZ(peer);
    dhGen(sk, pk);
    serialize_mpz(sockfd, pk);
    deserialize_mpz(peer, sockfd);

    unsigned char shared[64];
    dhFinal(sk, pk, peer, shared, sizeof(shared));
    memcpy(s->enc_key, shared, 32);
    memcpy(s->mac_key, shared + 32, 32);

    // Initialize AES-CTR contexts
    unsigned char iv[16] = {0};
    s->enc_ctx = EVP_CIPHER_CTX_new();
    s->dec_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(s->enc_ctx, EVP_aes_256_ctr(), NULL, s->enc_key, iv);
    EVP_DecryptInit_ex(s->dec_ctx, EVP_aes_256_ctr(), NULL, s->enc_key, iv);

    s->send_seq = 0;
    s->recv_seq = 0;
    return s;
}

int session_send(Session* s, const unsigned char* pt, size_t ptlen) {
    uint64_t seq_be = htobe64(s->send_seq++);
    size_t payload_len = ptlen + sizeof(seq_be);
    unsigned char* payload = malloc(payload_len);
    memcpy(payload, &seq_be, sizeof(seq_be));
    memcpy(payload + sizeof(seq_be), pt, ptlen);

    // Encrypt
    int ctlen;
    unsigned char* ct = malloc(payload_len);
    EVP_EncryptInit_ex(s->enc_ctx, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate(s->enc_ctx, ct, &ctlen, payload, payload_len);

    // HMAC-SHA256
    unsigned char tag[32]; unsigned int taglen;
    HMAC(EVP_sha256(), s->mac_key, 32, ct, ctlen, tag, &taglen);

    // Send: [4-byte len][ciphertext][tag]
    uint32_t netlen = htonl(ctlen);
    xwrite(s->sockfd, &netlen, 4);
    xwrite(s->sockfd, ct, ctlen);
    xwrite(s->sockfd, tag, taglen);

    free(payload);
    free(ct);
    return 0;
}

int session_recv(Session* s, unsigned char** out, size_t* outlen) {
    uint32_t netlen;
    xread(s->sockfd, &netlen, 4);
    uint32_t ctlen = ntohl(netlen);

    unsigned char* ct = malloc(ctlen);
    xread(s->sockfd, ct, ctlen);
    unsigned char tag[32];
    xread(s->sockfd, tag, sizeof(tag));

    // Verify HMAC
    unsigned char calc[32]; unsigned int calc_len;
    HMAC(EVP_sha256(), s->mac_key, 32, ct, ctlen, calc, &calc_len);
    if (calc_len != sizeof(calc) || memcmp(calc, tag, sizeof(tag))) {
        free(ct);
        return -1;
    }

    // Decrypt
    unsigned char* pt_full = malloc(ctlen);
    int ptlen;
    EVP_DecryptInit_ex(s->dec_ctx, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(s->dec_ctx, pt_full, &ptlen, ct, ctlen);

    uint64_t seq_be;
    memcpy(&seq_be, pt_full, sizeof(seq_be));
    uint64_t seq = be64toh(seq_be);
    if (seq <  s->recv_seq) {
        free(ct);
        free(pt_full);
        return -1;
    }
    s->recv_seq = seq;

    *outlen = ptlen - sizeof(seq_be);
    *out = malloc(*outlen);
    memcpy(*out, pt_full + sizeof(seq_be), *outlen);

    free(ct);
    free(pt_full);
    return 0;
}

void session_destroy(Session* s) {
    OPENSSL_cleanse(s->enc_key, 32);
    OPENSSL_cleanse(s->mac_key, 32);
    EVP_CIPHER_CTX_free(s->enc_ctx);
    EVP_CIPHER_CTX_free(s->dec_ctx);
    free(s);
}
