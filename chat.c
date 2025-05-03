#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
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

// Prototypes for mutual-auth helpers
EVP_PKEY* load_private_key(const char* path);
EVP_PKEY* load_public_key(const char* path);
int sign_buffer(EVP_PKEY* priv,
                const unsigned char* msg, size_t msglen,
                unsigned char** sig_out, size_t* siglen_out);
int verify_buffer(EVP_PKEY* pub,
                  const unsigned char* msg, size_t msglen,
                  const unsigned char* sig, size_t siglen);

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

int test_sign_verify(EVP_PKEY* priv, EVP_PKEY* pub, unsigned char* digest, size_t dlen) {
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


/* Perform ephemeral DH, derive symm_key, then mutual-auth handshake */
static unsigned char *g_my_pub, *g_peer_pub;
static size_t g_my_pub_len, g_peer_pub_len;
static void perform_handshake() {
    // Ephemeral X25519 Diffie-Hellman
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

    // expand our 32-byte symm_key into two 32-byte keys via SHA-512
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


        // compute transcript hash using SHA256 (as in your snippet)
    SHA256_CTX sha_ctx;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha_ctx);
    // order by lexicographic of public bytes for consistency
    if (memcmp(g_my_pub, g_peer_pub, g_my_pub_len) < 0) {
        SHA256_Update(&sha_ctx, g_my_pub,     g_my_pub_len);
        SHA256_Update(&sha_ctx, g_peer_pub,   g_peer_pub_len);
    } else {
        SHA256_Update(&sha_ctx, g_peer_pub,   g_peer_pub_len);
        SHA256_Update(&sha_ctx, g_my_pub,     g_my_pub_len);
    }
    SHA256_Update(&sha_ctx, (unsigned char*)"handshake", 9);
    SHA256_Final(digest, &sha_ctx);

        // debug print the digest
    fprintf(stderr, "[DEBUG] digest: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) fprintf(stderr, "%02x", digest[i]);
    fprintf(stderr, "");

// load long-term keys for self-test
    EVP_PKEY *my_priv = load_private_key("my_priv.pem");
    EVP_PKEY *peer_long = load_public_key("my_pub.pem");
    // self-test sign+verify locally before network exchange
    test_sign_verify(my_priv, peer_long, digest, SHA256_DIGEST_LENGTH);

    // mutual signature exchange on digest
    unsigned char *sig = NULL; size_t sig_len = 0;
    if (!sign_buffer(my_priv, digest, SHA256_DIGEST_LENGTH, &sig, &sig_len)) error("sign digest");

    // send our signature
    uint16_t sln = htons((uint16_t)sig_len);
    send(sockfd, &sln, sizeof(sln), MSG_WAITALL);
    send(sockfd, sig, sig_len, MSG_WAITALL);

    // receive peer signature length & signature
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
    EVP_PKEY_free(my_priv);
    EVP_PKEY_free(peer_long);
}

void* recvMsg(void*_) {
    while(1) {
        char buf[1024]; ssize_t l=recv(sockfd,buf,sizeof(buf),0);
        if(l<=0)break;
        char* m=malloc(l+1); memcpy(m,buf,l); m[l]='\0';
        g_idle_add(shownewmessage,m);
    }
    return NULL;
}

static void tsappend(const char*m,char**t,int nl) {
    GtkTextIter a; gtk_text_buffer_get_end_iter(tbuf,&a);
    size_t L=g_utf8_strlen(m,-1); char*tmp=NULL;
    if(nl && m[L-1]!='\n') { tmp=malloc(L+2); memcpy(tmp,m,L); tmp[L]='\n'; tmp[L+1]='\0'; m=tmp; L++; }
    gtk_text_buffer_insert(tbuf,&a,m,L);
    if(tmp) free(tmp);
    gtk_text_buffer_add_mark(tbuf,mark,&a);
    gtk_text_view_scroll_to_mark(tview,mark,0,TRUE,0,0);
}
static void sendMessage(GtkWidget*w,gpointer){
    char* tag[]={"self",NULL}; tsappend("me: ",tag,0);
    GtkTextIter s,e; gtk_text_buffer_get_bounds(mbuf,&s,&e);
    char* msg=gtk_text_buffer_get_text(mbuf,&s,&e,TRUE);
    size_t L=g_utf8_strlen(msg,-1);
    unsigned char*enc=malloc(L);
    for(size_t i=0;i<L;i++) enc[i]=msg[i]^symm_key[i%symm_key_len];
    send(sockfd,enc,L,0); free(enc);
    tsappend(msg,NULL,1); free(msg);
    gtk_text_buffer_delete(mbuf,&s,&e);
}
static gboolean shownewmessage(gpointer msg) {
    char* tag[]={"friend",NULL}; tsappend("fr: ",tag,0);
    char* ct=msg; size_t L=strlen(ct);
    for(size_t i=0;i<L;i++) ct[i]^=symm_key[i%symm_key_len];
    tsappend(ct,NULL,1); free(ct);
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
    mark=gtk_text_mark_new(NULL,TRUE);
    tview=GTK_TEXT_VIEW(gtk_builder_get_object(b,"transcript"));
    mbuf=gtk_text_view_get_buffer(GTK_TEXT_VIEW(gtk_builder_get_object(b,"message")));
    tbuf=gtk_text_view_get_buffer(tview);
    g_signal_connect(gtk_builder_get_object(b,"send"),"clicked",G_CALLBACK(sendMessage),NULL);
    pthread_create(&trecv,NULL,recvMsg,NULL);
    gtk_main();
    shutdownNetwork();
    return 0;
}
