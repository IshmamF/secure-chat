// mutual_auth.c
#include "mutual_auth.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// load private key from PEM
EVP_PKEY* load_private_key(const char* f) {
    FILE* fp = fopen(f,"r"); if(!fp){perror("fopen priv");return NULL;}
    EVP_PKEY* k = PEM_read_PrivateKey(fp,NULL,NULL,NULL);
    fclose(fp);
    if(!k) fprintf(stderr,"priv load error: %s\n",ERR_error_string(ERR_get_error(),NULL));
    return k;
}
// load public key from PEM
EVP_PKEY* load_public_key(const char* f) {
    FILE* fp = fopen(f,"r"); if(!fp){perror("fopen pub");return NULL;}
    EVP_PKEY* k = PEM_read_PUBKEY(fp,NULL,NULL,NULL);
    fclose(fp);
    if(!k) fprintf(stderr,"pub load error: %s\n",ERR_error_string(ERR_get_error(),NULL));
    return k;
}
// sign buffer
int sign_buffer(EVP_PKEY* pk,
                    const unsigned char* m, size_t mlen,
                    unsigned char** sig, size_t* slen)
{
    EVP_MD_CTX* c = EVP_MD_CTX_new(); if(!c) return 0;
    if(EVP_DigestSignInit(c,NULL,EVP_sha256(),NULL,pk)<=0) goto err;
    if(EVP_DigestSignUpdate(c,m,mlen)<=0) goto err;
    if(EVP_DigestSignFinal(c,NULL,slen)<=0) goto err;
    *sig = malloc(*slen);
    if(EVP_DigestSignFinal(c,*sig,slen)<=0) goto err;
    EVP_MD_CTX_free(c); return 1;
err:
    EVP_MD_CTX_free(c); return 0;
}
// verify buffer
int verify_buffer(EVP_PKEY* pk,
                      const unsigned char* m, size_t mlen,
                      const unsigned char* s, size_t slen)
{
    EVP_MD_CTX* c = EVP_MD_CTX_new(); if(!c) return 0;
    if(EVP_DigestVerifyInit(c,NULL,EVP_sha256(),NULL,pk)<=0) goto err;
    if(EVP_DigestVerifyUpdate(c,m,mlen)<=0) goto err;
    int r = EVP_DigestVerifyFinal(c,s,slen);
    EVP_MD_CTX_free(c);
    return r==1;
err:
    EVP_MD_CTX_free(c); return 0;
}

int mutual_authenticate(const char* my_privkey_file,
                        const char* peer_pubkey_file,
                        const unsigned char* my_pub,   size_t my_pub_len,
                        const unsigned char* peer_pub, size_t peer_pub_len,
                        int sockfd,
                        int is_client)
{
    EVP_PKEY* my_priv  = load_private_key(my_privkey_file);
    EVP_PKEY* peer_long= load_public_key(peer_pubkey_file);
    if(!my_priv||!peer_long){ EVP_PKEY_free(my_priv); EVP_PKEY_free(peer_long); return 0; }

    unsigned char *my_sig   = NULL;
    size_t        my_sig_len=0;
    unsigned char *peer_sig = NULL;
    size_t        peer_sig_len=0;
    uint16_t      net16;

    if(is_client) {
        // client: sign & send first
        if(!sign_buffer(my_priv, my_pub, my_pub_len, &my_sig, &my_sig_len)){
            fprintf(stderr,"sign failed\n"); goto fail;
        }
        net16 = htons((uint16_t)my_sig_len);
        send(sockfd,&net16,2,0);
        send(sockfd,my_sig,my_sig_len,0);

        // then receive peer signature
        recv(sockfd,&net16,2,MSG_WAITALL);
        peer_sig_len = ntohs(net16);
        peer_sig = malloc(peer_sig_len);
        recv(sockfd,peer_sig,peer_sig_len,MSG_WAITALL);
    }
    else {
        // server: receive first
        recv(sockfd,&net16,2,MSG_WAITALL);
        peer_sig_len = ntohs(net16);
        peer_sig = malloc(peer_sig_len);
        recv(sockfd,peer_sig,peer_sig_len,MSG_WAITALL);

        // then sign & send
        if(!sign_buffer(my_priv, my_pub, my_pub_len, &my_sig, &my_sig_len)){
            fprintf(stderr,"sign failed\n"); goto fail;
        }
        net16 = htons((uint16_t)my_sig_len);
        send(sockfd,&net16,2,0);
        send(sockfd,my_sig,my_sig_len,0);
    }

    // verify peer signature on peer_pub
    if(verify_buffer(peer_long, peer_pub, peer_pub_len, peer_sig, peer_sig_len)){
        fprintf(stderr,"Mutual auth success\n");
    } else {
        fprintf(stderr,"Mutual auth FAILED\n");
        goto fail;
    }

    free(my_sig);
    free(peer_sig);
    EVP_PKEY_free(my_priv);
    EVP_PKEY_free(peer_long);
    return 1;

fail:
    free(my_sig);
    free(peer_sig);
    EVP_PKEY_free(my_priv);
    EVP_PKEY_free(peer_long);
    return 0;
}
