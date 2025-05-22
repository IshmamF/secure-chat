// chat.c
#include <gtk/gtk.h>
#include <glib/gunicode.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>  // for HMAC()
#include <getopt.h>
#include <stdint.h>
#include "dh.h"
#include "keys.h"
#include "mutual_auth.h"
#include <limits.h>
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifdef __APPLE__
  #include <libkern/OSByteOrder.h>
  #define htobe64(x) OSSwapHostToBigInt64(x)
  #define be64toh(x) OSSwapBigToHostInt64(x)
#else
  #include <endian.h>   
#endif

EVP_PKEY* load_private_key(const char* path);
EVP_PKEY* load_public_key(const char* path);
int sign_buffer(EVP_PKEY* priv,
                const unsigned char* msg, size_t msglen,
                unsigned char** sig_out, size_t* siglen_out);
int verify_buffer(EVP_PKEY* pub,
                  const unsigned char* msg, size_t msglen,
                  const unsigned char* sig, size_t siglen);
static void test_sign_verify(EVP_PKEY* priv,
                             EVP_PKEY* pub,
                             unsigned char* digest,
                             size_t dlen);

static gboolean shownewmessage(gpointer msg);
static GtkTextBuffer* tbuf;
static GtkTextBuffer* mbuf;
static GtkTextView*  tview;
static GtkTextMark*   mark;
static pthread_t trecv;
void* recvMsg(void*);
static int listensock, sockfd;
static int isclient = 1;
static unsigned char symm_key[32];
static const size_t symm_key_len = sizeof(symm_key);
static uint64_t send_seq = 0;        
static uint64_t recv_seq_expected = 0;


static void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* Ephemeral X25519 key ops */
static EVP_PKEY* generate_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0)
        error("Key generation failed");
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}
static void get_public(EVP_PKEY *pkey, unsigned char **pub, size_t *pub_len) {
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, pub_len) <= 0) error("publen failed");
    *pub = malloc(*pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, *pub, pub_len) <= 0) error("get pub failed");
}
static void derive_shared(EVP_PKEY *local, EVP_PKEY *peer) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer) <= 0) error("derive init");
    size_t slen; EVP_PKEY_derive(ctx, NULL, &slen);
    unsigned char *secret = malloc(slen);
    EVP_PKEY_derive(ctx, secret, &slen);
    SHA256(secret, slen, symm_key);
    free(secret);
    EVP_PKEY_CTX_free(ctx);
}

int initServerNet(int port) {
    int reuse = 1;
    struct sockaddr_in addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock<0) error("sock");
    bzero(&addr, sizeof(addr)); addr.sin_family=AF_INET; addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(port);
    bind(listensock,(struct sockaddr*)&addr,sizeof(addr));
    listen(listensock,1);
    socklen_t cl=sizeof(addr);
    sockfd=accept(listensock,(struct sockaddr*)&addr,&cl);
    close(listensock);
    fprintf(stderr,"server: handshake...\n");
    return 0;
}
static int initClientNet(const char* host,int port) {
    struct sockaddr_in addr; struct hostent*h;
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    h=gethostbyname(host); if(!h) error("nhost");
    bzero(&addr,sizeof(addr)); addr.sin_family=AF_INET;
    memcpy(&addr.sin_addr.s_addr,h->h_addr,h->h_length);
    addr.sin_port=htons(port);
    connect(sockfd,(struct sockaddr*)&addr,sizeof(addr));
    fprintf(stderr,"client: handshake...\n");
    return 0;
}
static int shutdownNetwork() {
    shutdown(sockfd,2);
    unsigned char buf[64]; while(recv(sockfd,buf,64,0)>0);
    close(sockfd);
    return 0;
}

static void test_sign_verify(EVP_PKEY* priv,
                             EVP_PKEY* pub,
                             unsigned char* digest,
                             size_t dlen) {
    unsigned char *sig = NULL;
    size_t siglen = 0;
    if (!sign_buffer(priv, digest, dlen, &sig, &siglen)) {
        fprintf(stderr, "LOCAL sign failed");
    } else if (!verify_buffer(pub, digest, dlen, sig, siglen)) {
        fprintf(stderr, "LOCAL verify failed");
    } else {
        fprintf(stderr, "LOCAL sign+verify OK");
    }
    free(sig);
}


static unsigned char *g_my_pub, *g_peer_pub;
static size_t g_my_pub_len, g_peer_pub_len;
static void perform_handshake() {
    EVP_PKEY *mine = generate_key();
    unsigned char* mpub; size_t mlen;
    get_public(mine, &mpub, &mlen);
    uint16_t ln;
    if (isclient) {
        ln = htons(mlen); send(sockfd, &ln, 2, 0);
        send(sockfd, mpub, mlen, 0);
        recv(sockfd, &ln, 2, MSG_WAITALL); g_peer_pub_len = ntohs(ln);
        g_peer_pub = malloc(g_peer_pub_len);
        recv(sockfd, g_peer_pub, g_peer_pub_len, MSG_WAITALL);
    } else {
        recv(sockfd, &ln, 2, MSG_WAITALL); g_peer_pub_len = ntohs(ln);
        g_peer_pub = malloc(g_peer_pub_len);
        recv(sockfd, g_peer_pub, g_peer_pub_len, MSG_WAITALL);
        ln = htons(mlen); send(sockfd, &ln, 2, 0);
        send(sockfd, mpub, mlen, 0);
    }
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, g_peer_pub, g_peer_pub_len);
    derive_shared(mine, peer);
    g_my_pub = mpub; g_my_pub_len = mlen;
    EVP_PKEY_free(mine); EVP_PKEY_free(peer);
    fprintf(stderr, "ephemeral DH done\n");

    unsigned char keymat[64];
    SHA512(symm_key, symm_key_len, keymat);

    unsigned char session_k_enc[32];
    unsigned char session_k_mac[32];
    memcpy(session_k_enc, keymat,       32);
    memcpy(session_k_mac, keymat + 32,  32);

    fprintf(stderr, "Shared AES key: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", session_k_enc[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "Shared HMAC key: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", session_k_mac[i]);
    fprintf(stderr, "\n");

    SHA256_CTX sha_ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    if (memcmp(g_my_pub, g_peer_pub, g_my_pub_len) < 0) {
        SHA256_Update(&sha_ctx, g_my_pub,     g_my_pub_len);
        SHA256_Update(&sha_ctx, g_peer_pub,   g_peer_pub_len);
    } else {
        SHA256_Update(&sha_ctx, g_peer_pub,   g_peer_pub_len);
        SHA256_Update(&sha_ctx, g_my_pub,     g_my_pub_len);
    }
    SHA256_Update(&sha_ctx, (unsigned char*)"handshake", 9);
    SHA256_Final(digest, &sha_ctx);

    fprintf(stderr, "[DEBUG] digest: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(stderr, "%02x", digest[i]);
    fprintf(stderr, "\n");

    EVP_PKEY *my_priv = load_private_key("my_priv.pem");
    EVP_PKEY *peer_long = load_public_key("my_pub.pem");
    test_sign_verify(my_priv, peer_long, digest, SHA256_DIGEST_LENGTH);

    unsigned char *sig = NULL; size_t sig_len = 0;
    if (!sign_buffer(my_priv, digest, SHA256_DIGEST_LENGTH, &sig, &sig_len)) error("sign digest");

    uint16_t sln = htons((uint16_t)sig_len);
    send(sockfd, &sln, sizeof(sln), MSG_WAITALL);
    send(sockfd, sig, sig_len, MSG_WAITALL);

    uint16_t prn;

    ssize_t got = recv(sockfd, &prn, sizeof(prn), MSG_WAITALL);
    size_t peer_sig_len = ntohs(prn);
    fprintf(stderr,"[DEBUG] recv length field got=%zd expected=%zu\n", got, sizeof(prn));
    unsigned char *peer_sig = malloc(peer_sig_len);
    if (!peer_sig) error("malloc peer_sig");
    got = recv(sockfd, peer_sig, peer_sig_len, MSG_WAITALL);
    fprintf(stderr,"[DEBUG] recv sig      got=%zd expected=%zu\n", got, peer_sig_len);

    if (!verify_buffer(peer_long, digest, SHA256_DIGEST_LENGTH, peer_sig, peer_sig_len)) error("Signature verification failed");
    fprintf(stderr, "Signature verified successfully.");

    free(sig);
    free(peer_sig);
    EVP_PKEY_free(my_priv);
    EVP_PKEY_free(peer_long);
}

void* recvMsg(void*_) {
    uint64_t seq_net_be;
    uint32_t len_net_be;
    while (1) {
        ssize_t n = recv(sockfd, &seq_net_be, sizeof(seq_net_be), MSG_WAITALL);
        if (n != sizeof(seq_net_be)) break;
        uint64_t seq = be64toh(seq_net_be);

        n = recv(sockfd, &len_net_be, sizeof(len_net_be), MSG_WAITALL);
        if (n != sizeof(len_net_be)) break;
        size_t L = ntohl(len_net_be);

        if (seq < recv_seq_expected) {
            fprintf(stderr, "[DEBUG] replay detected: seq %" PRIu64 " < expected %" PRIu64 "", seq, recv_seq_expected);
            // drain unread bytes (ciphertext + tag)
            size_t toskip = L + 32;
            unsigned char tmp[1024];
            while (toskip > 0) {
                size_t chunk = toskip < sizeof(tmp) ? toskip : sizeof(tmp);
                n = recv(sockfd, tmp, chunk, MSG_WAITALL);
                if (n <= 0) break;
                toskip -= n;
            }
            continue;
        }

        unsigned char *ciphertext = malloc(L);
        if (!ciphertext) break;
        n = recv(sockfd, ciphertext, L, MSG_WAITALL);
        if (n != (ssize_t)L) { free(ciphertext); break; }

        unsigned char tagbuf[32];
        n = recv(sockfd, tagbuf, sizeof(tagbuf), MSG_WAITALL);
        if (n != (ssize_t)sizeof(tagbuf)) { free(ciphertext); break; }

        fprintf(stderr, "[RAW RECV] seq=%" PRIu64 " len=%zu ct=", seq, L);
        for(size_t i = 0; i < L; i++) fprintf(stderr, "%02x", ciphertext[i]);
        fprintf(stderr, " tag=");
        for(size_t i = 0; i < sizeof(tagbuf); i++) fprintf(stderr, "%02x", tagbuf[i]);
        fprintf(stderr, "\n");


        HMAC_CTX *hctx = HMAC_CTX_new();
        unsigned char tag2[32]; unsigned int tag2_len = 0;
        HMAC_Init_ex(hctx, symm_key, symm_key_len, EVP_sha256(), NULL);
        HMAC_Update(hctx, (unsigned char*)&seq_net_be, sizeof(seq_net_be));
        HMAC_Update(hctx, (unsigned char*)&len_net_be, sizeof(len_net_be));
        HMAC_Update(hctx, ciphertext, L);
        HMAC_Final(hctx, tag2, &tag2_len);
        HMAC_CTX_free(hctx);

        if (CRYPTO_memcmp(tagbuf, tag2, tag2_len) != 0) {
            fprintf(stderr, "[DEBUG] HMAC verification failed for seq %" PRIu64 "", seq);
            free(ciphertext);
            continue;
        }
        recv_seq_expected = seq + 1;

        char* pt = malloc(L+1);
        for (size_t i = 0; i < L; i++) pt[i] = ciphertext[i] ^ symm_key[i % symm_key_len];
        pt[L] = ' ';
        g_idle_add(shownewmessage, pt);
        free(ciphertext);
    }
    return NULL;
}


static void tsappend(const char *message, char **tagnames, int ensurenewline)
{
    GtkTextIter start, end;
    gtk_text_buffer_get_end_iter(tbuf, &end);

    g_autofree char *buf = g_strdup(message);
    size_t len = g_utf8_strlen(buf, -1);

    if (ensurenewline && len > 0 && buf[len-1] != '\n') {
        buf = g_realloc(buf, len + 2);
        buf[len++] = '\n';
        buf[len]   = '\0';
    }

    gtk_text_buffer_insert(tbuf, &end, buf, len);

    start = end;
    gtk_text_iter_backward_chars(&start, len);

    if (tagnames) {
        for (char **tag = tagnames; *tag; ++tag) {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &start, &end);
        }
    }

    if (!ensurenewline)
        return;

    gtk_text_buffer_add_mark(tbuf, mark, &end);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, FALSE, 0.0, 1.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}


static void sendMessage(GtkWidget* w, gpointer) {
    char* tag[] = {"self", NULL};
    tsappend("me: ", tag, 0);
    GtkTextIter s, e;
    gtk_text_buffer_get_bounds(mbuf, &s, &e);
    char* msg = gtk_text_buffer_get_text(mbuf, &s, &e, TRUE);
    size_t L = g_utf8_strlen(msg, -1);
    unsigned char* ciphertext = malloc(L);
    for (size_t i = 0; i < L; i++) {
        ciphertext[i] = msg[i] ^ symm_key[i % symm_key_len];
    }

    uint64_t seq_net = htobe64(++send_seq);
    uint32_t len_net = htonl((uint32_t)L);
    HMAC_CTX* hctx = HMAC_CTX_new();
    unsigned char tagbuf[32];
    unsigned int taglen = 0;
    HMAC_Init_ex(hctx, symm_key, symm_key_len, EVP_sha256(), NULL);
    HMAC_Update(hctx, (unsigned char*)&seq_net, sizeof(seq_net));
    HMAC_Update(hctx, (unsigned char*)&len_net, sizeof(len_net));
    HMAC_Update(hctx, ciphertext, L);
    HMAC_Final(hctx, tagbuf, &taglen);
    HMAC_CTX_free(hctx);
    send(sockfd, &seq_net,   sizeof(seq_net), 0);
    send(sockfd, &len_net,   sizeof(len_net), 0);
    send(sockfd, ciphertext, L,               0);
    send(sockfd, tagbuf,     taglen,           0);
    fprintf(stderr, "[RAW SEND] seq=%" PRIu64 " len=%u ct=", send_seq, (uint32_t)L);
    for(size_t i = 0; i < L; i++) fprintf(stderr, "%02x", ciphertext[i]);
    fprintf(stderr, " tag=");
    for(unsigned int i = 0; i < taglen; i++) fprintf(stderr, "%02x", tagbuf[i]);
    fprintf(stderr, "\n");
    tsappend(msg, NULL, 1);
    gtk_text_buffer_delete(mbuf, &s, &e);
    free(msg);
    free(ciphertext);
}


static gboolean shownewmessage(gpointer msg) {
    char* plaintext = msg;
    tsappend( "friend: ", NULL, 0 );  // no tag colors, or define tags
    tsappend(plaintext,    NULL, 1);
    free(plaintext);
    return FALSE;
}

int main(int c,char**v){
    int port=1337; char host[HOST_NAME_MAX+1]="localhost";
    static struct option o[]={{"connect",1,0,'c'},{"listen",0,0,'l'},{"port",1,0,'p'},{0,0,0,0}};
    int idx; char ch;
    while((ch=getopt_long(c,v,"c:lp:",o,&idx))!=-1){
        if(ch=='c') strncpy(host,optarg,HOST_NAME_MAX);
        else if(ch=='l') isclient=0;
        else if(ch=='p') port=atoi(optarg);
    }
    if(isclient) initClientNet(host,port);
    else         initServerNet(port);

    perform_handshake();

    // mutual authentication already done inside perform_handshake()
    // skip the extra mutual_authenticate() call

    gtk_init(&c,&v);
    GtkBuilder*b=gtk_builder_new(); GError*err=NULL;
    gtk_builder_add_from_file(b,"layout.ui",&err);
    if (err) {
        g_printerr("Error loading layout.ui: %s\n", err->message);
        g_error_free(err);
        exit(1);
    }

    tview=GTK_TEXT_VIEW(gtk_builder_get_object(b,"transcript"));
    if (!GTK_IS_TEXT_VIEW(tview)) {
        g_printerr("Couldn't find TextView 'transcript' in layout.ui\n");
        exit(1);
    }
    mbuf=gtk_text_view_get_buffer(GTK_TEXT_VIEW(gtk_builder_get_object(b,"message")));
    tbuf=gtk_text_view_get_buffer(tview);
    if (!GTK_IS_TEXT_BUFFER(tbuf)) {
        g_printerr("Couldn't get buffer from TextView\n");
        exit(1);
    }

    GtkTextIter iter;
    gtk_text_buffer_get_end_iter(tbuf, &iter);
    mark = gtk_text_buffer_create_mark(tbuf, "end", &iter, TRUE);
    if (!GTK_IS_TEXT_MARK(mark)) {
        g_printerr("Failed to create mark\n");
        exit(1);
    }


    g_signal_connect(gtk_builder_get_object(b,"send"),"clicked",G_CALLBACK(sendMessage),NULL);
    pthread_create(&trecv,NULL,recvMsg,NULL);
    gtk_main();
    shutdownNetwork();
    return 0;
}
