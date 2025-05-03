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
#include <limits.h>
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

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

static EVP_PKEY* generate_key() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL;
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        error("Key generation failed");
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static void get_public(EVP_PKEY *pkey, unsigned char **pub, size_t *pub_len) {
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, pub_len) <= 0)
        error("Getting pubkey length failed");
    *pub = malloc(*pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, *pub, pub_len) <= 0)
        error("Getting pubkey failed");
}

static void derive_shared(EVP_PKEY *local, EVP_PKEY *peer) {
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(local, NULL);
    if (!dctx || EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, peer) <= 0)
        error("Derive init failed");
    size_t secret_len;
    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0)
        error("Secret length failed");
    unsigned char *secret = malloc(secret_len);
    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0)
        error("Secret derivation failed");
    SHA256(secret, secret_len, symm_key);
    EVP_PKEY_CTX_free(dctx);
    free(secret);
}

int initServerNet(int port) {
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0) error("ERROR opening socket");
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr*)&cli_addr, &clilen);
    if (sockfd < 0) error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, performing handshake...\n");
    return 0;
}

static int initClientNet(char* hostname, int port) {
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0) error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (!server) { fprintf(stderr, "ERROR, no such host\n"); exit(0); }
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    fprintf(stderr, "connected, performing handshake...\n");
    return 0;
}

static int shutdownNetwork() {
    shutdown(sockfd, 2);
    unsigned char dummy[64]; ssize_t r;
    do { r = recv(sockfd, dummy, 64, 0); } while (r > 0);
    close(sockfd);
    return 0;
}

static void perform_handshake() {
    EVP_PKEY *local = generate_key();
    unsigned char *local_pub; size_t local_pub_len;
    get_public(local, &local_pub, &local_pub_len);
    unsigned char *peer_pub; size_t peer_pub_len; uint16_t len_net;
    if (isclient) {
        len_net = htons(local_pub_len);
        send(sockfd, &len_net, sizeof(len_net), 0);
        send(sockfd, local_pub, local_pub_len, 0);
        recv(sockfd, &len_net, sizeof(len_net), MSG_WAITALL);
        peer_pub_len = ntohs(len_net);
        peer_pub = malloc(peer_pub_len);
        recv(sockfd, peer_pub, peer_pub_len, MSG_WAITALL);
    } else {
        recv(sockfd, &len_net, sizeof(len_net), MSG_WAITALL);
        peer_pub_len = ntohs(len_net);
        peer_pub = malloc(peer_pub_len);
        recv(sockfd, peer_pub, peer_pub_len, MSG_WAITALL);
        len_net = htons(local_pub_len);
        send(sockfd, &len_net, sizeof(len_net), 0);
        send(sockfd, local_pub, local_pub_len, 0);
    }
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub, peer_pub_len);
    derive_shared(local, peer);
    free(local_pub); free(peer_pub);
    EVP_PKEY_free(local); EVP_PKEY_free(peer);
    fprintf(stderr, "handshake complete, secure channel established.\n");
}

void* recvMsg(void* arg) {
    (void)arg;
    while (1) {
        char buf[1024]; ssize_t len = recv(sockfd, buf, sizeof(buf), 0);
        if (len <= 0) break;
        char* msg = malloc(len+1);
        memcpy(msg, buf, len);
        msg[len] = '\0';
        g_idle_add(shownewmessage, msg);
    }
    return NULL;
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat with PFS handshake.\n\n"
"  -c, --connect HOST   connect to HOST\n"
"  -l, --listen         listen mode\n"
"  -p, --port PORT      port (default 1337)\n"
"  -h, --help           this message\n";

static void tsappend(char* message, char** tagnames, int ensurenewline) {
    GtkTextIter t0; gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len-1] != '\n') message[len++]='\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1; gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1; gtk_text_iter_backward_chars(&t0, len);
    if (tagnames) for(char** tag=tagnames; *tag; ++tag)
        gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
    if (!ensurenewline) return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, TRUE, 0.0,0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

static void sendMessage(GtkWidget* w, gpointer) {
    char* tags[] = {"self",NULL}; tsappend("me: ",tags,0);
    GtkTextIter s,e; gtk_text_buffer_get_start_iter(mbuf,&s);
    gtk_text_buffer_get_end_iter(mbuf,&e);
    char* message=gtk_text_buffer_get_text(mbuf,&s,&e,TRUE);
    size_t len=g_utf8_strlen(message,-1);
    unsigned char* enc=malloc(len);
    for(size_t i=0;i<len;i++) enc[i]=message[i]^symm_key[i%symm_key_len];
    if(send(sockfd,enc,len,0)==-1) error("send failed"); free(enc);
    tsappend(message,NULL,1); free(message);
    gtk_text_buffer_delete(mbuf,&s,&e); gtk_widget_grab_focus(w);
}

static gboolean shownewmessage(gpointer msg) {
    char* tags[] = {"friend",NULL}; tsappend("friend: ",tags,0);
    char* ct=(char*)msg; size_t len=strlen(ct);
    for(size_t i=0;i<len;i++) ct[i]^=symm_key[i%symm_key_len];
    tsappend(ct,NULL,1); free(msg); return FALSE;
}

int main(int argc,char*argv[]){
    if(init("params")!=0){fprintf(stderr,"could not read DH params\n");return 1;}
    struct option opts[]={{"connect",1,0,'c'},{"listen",0,0,'l'},{"port",1,0,'p'},{"help",0,0,'h'},{0,0,0,0}};
    int port=1337; char hostname[HOST_NAME_MAX+1]="localhost"; int c,idx;
    while((c=getopt_long(argc,argv,"c:lp:h",opts,&idx))!=-1){
        switch(c){case 'c':strncpy(hostname,optarg,HOST_NAME_MAX);break;
                   case 'l':isclient=0;break;case 'p':port=atoi(optarg);break;
                   case 'h':printf(usage,argv[0]);return 0;}
    }
    if(isclient)initClientNet(hostname,port);else initServerNet(port);
    perform_handshake();
    gtk_init(&argc,&argv);
    GtkBuilder* b=gtk_builder_new();GError*err=NULL;
    if(!gtk_builder_add_from_file(b,"layout.ui",&err)){g_printerr("Error: %s\n",err->message);return 1;}
    mark=gtk_text_mark_new(NULL,TRUE);
    tview=GTK_TEXT_VIEW(gtk_builder_get_object(b,"transcript"));
    mbuf=gtk_text_view_get_buffer(GTK_TEXT_VIEW(gtk_builder_get_object(b,"message")));
    tbuf=gtk_text_view_get_buffer(tview);
    g_signal_connect(gtk_builder_get_object(b,"send"),"clicked",G_CALLBACK(sendMessage),NULL);
    gtk_widget_grab_focus(GTK_WIDGET(gtk_builder_get_object(b,"message")));
    GtkCssProvider*css=gtk_css_provider_new();
    gtk_css_provider_load_from_path(css,"colors.css",NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),GTK_STYLE_PROVIDER(css),GTK_STYLE_PROVIDER_PRIORITY_USER);
    pthread_create(&trecv,NULL,recvMsg,NULL);
    gtk_main(); shutdownNetwork(); return 0;
}