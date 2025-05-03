#include "mutual-auth.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Load our private key from PEM file
static EVP_PKEY* load_private_key(const char* keyfile) {
    FILE* f = fopen(keyfile, "r");
    if (!f) { perror("fopen private key"); return NULL; }
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) fprintf(stderr, "Error loading private key: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return pkey;
}

// Load peer's public key from PEM file
static EVP_PKEY* load_public_key(const char* certfile) {
    FILE* f = fopen(certfile, "r");
    if (!f) { perror("fopen public key"); return NULL; }
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) fprintf(stderr, "Error loading public key: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return pkey;
}

// Sign data buffer
static int sign_buffer(EVP_PKEY* priv, const unsigned char* msg, size_t msglen,
                       unsigned char** sig, size_t* siglen) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) <= 0) goto err;
    if (EVP_DigestSignUpdate(ctx, msg, msglen) <= 0) goto err;
    if (EVP_DigestSignFinal(ctx, NULL, siglen) <= 0) goto err;
    *sig = malloc(*siglen);
    if (EVP_DigestSignFinal(ctx, *sig, siglen) <= 0) goto err;
    EVP_MD_CTX_free(ctx);
    return 1;
err:
    EVP_MD_CTX_free(ctx);
    return 0;
}

// Verify signature on data buffer
static int verify_buffer(EVP_PKEY* pub, const unsigned char* msg, size_t msglen,
                         const unsigned char* sig, size_t siglen) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) <= 0) goto err;
    if (EVP_DigestVerifyUpdate(ctx, msg, msglen) <= 0) goto err;
    int rc = EVP_DigestVerifyFinal(ctx, sig, siglen);
    EVP_MD_CTX_free(ctx);
    return rc == 1;
err:
    EVP_MD_CTX_free(ctx);
    return 0;
}

int mutual_authenticate(const char* my_privkey_file,
                        const char* peer_pubkey_file,
                        const unsigned char* my_pub, size_t my_pub_len,
                        const unsigned char* peer_pub, size_t peer_pub_len,
                        int sockfd) {
    EVP_PKEY* my_priv = load_private_key(my_privkey_file);
    EVP_PKEY* peer_longterm_pub = load_public_key(peer_pubkey_file);
    if (!my_priv || !peer_longterm_pub) return 0;

    // Sign our ephemeral public key
    unsigned char* my_sig = NULL;
    size_t my_sig_len = 0;
    if (!sign_buffer(my_priv, my_pub, my_pub_len, &my_sig, &my_sig_len)) {
        fprintf(stderr, "Signing failed\n");
        EVP_PKEY_free(my_priv);
        EVP_PKEY_free(peer_longterm_pub);
        return 0;
    }

    // Send signature length and signature
    uint16_t net_len = htons((uint16_t)my_sig_len);
    if (send(sockfd, &net_len, sizeof(net_len), 0) != sizeof(net_len) ||
        send(sockfd, my_sig, my_sig_len, 0) != (ssize_t)my_sig_len) {
        perror("send");
        free(my_sig);
        EVP_PKEY_free(my_priv);
        EVP_PKEY_free(peer_longterm_pub);
        return 0;
    }

    // Receive peer's signature length and signature
    uint16_t peer_sig_len_net;
    if (recv(sockfd, &peer_sig_len_net, sizeof(peer_sig_len_net), MSG_WAITALL) != sizeof(peer_sig_len_net)) {
        perror("recv len"); free(my_sig);
        EVP_PKEY_free(my_priv); EVP_PKEY_free(peer_longterm_pub);
        return 0;
    }
    size_t peer_sig_len = ntohs(peer_sig_len_net);
    unsigned char* peer_sig = malloc(peer_sig_len);
    if (recv(sockfd, peer_sig, peer_sig_len, MSG_WAITALL) != (ssize_t)peer_sig_len) {
        perror("recv sig"); free(my_sig); free(peer_sig);
        EVP_PKEY_free(my_priv); EVP_PKEY_free(peer_longterm_pub);
        return 0;
    }

    // Verify peer's signature on our ephemeral public
    int ok = verify_buffer(peer_longterm_pub, my_pub, my_pub_len, peer_sig, peer_sig_len);
    if (!ok) fprintf(stderr, "Mutual auth failed: invalid signature\n");

    // Cleanup
    free(my_sig);
    free(peer_sig);
    EVP_PKEY_free(my_priv);
    EVP_PKEY_free(peer_longterm_pub);
    return ok;
}
