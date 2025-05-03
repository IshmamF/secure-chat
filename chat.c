// chat.c
#include <gtk/gtk.h>
#include <glib/gunicode.h>    /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include "session.h"          // your session_create/send/recv

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif
#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf;
static GtkTextBuffer* mbuf;
static GtkTextView*  tview;
static GtkTextMark*   mark;
static pthread_t      trecv;
static Session*       sess;

void* recvMsg(void*);

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg) { perror(msg); exit(EXIT_FAILURE); }

int initServerNet(int port) {
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR,
               &reuse, sizeof(reuse));
    if (listensock < 0) error("ERROR opening socket");
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port        = htons(port);
    if (bind(listensock,
             (struct sockaddr*)&serv_addr,
             sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen = sizeof(serv_addr);
    sockfd = accept(listensock,
                   (struct sockaddr*)&serv_addr,
                   &clilen);
    if (sockfd < 0) error("ERROR on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(const char* host, int port) {
    struct hostent* hp;
    struct sockaddr_in sa;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");
    hp = gethostbyname(host);
    if (!hp) error("ERROR, no such host");
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    memcpy(&sa.sin_addr, hp->h_addr_list[0], hp->h_length);
    sa.sin_port = htons(port);
    if (connect(sockfd,
                (struct sockaddr*)&sa,
                sizeof(sa)) < 0)
        error("ERROR connecting");
    return 0;
}

static int shutdownNetwork() {
    shutdown(sockfd, SHUT_RDWR);
    char dummy[64];
    while (recv(sockfd, dummy, sizeof(dummy), 0) > 0);
    close(sockfd);
    return 0;
}

static void tsappend(const char* msg,
                     char** tags,
                     int newline) {
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(tbuf, &end);
    gtk_text_buffer_insert(tbuf, &end, msg, -1);
    if (newline) {
        gtk_text_buffer_add_mark(tbuf, mark, &end);
        gtk_text_view_scroll_to_mark(tview, mark,
                                     0.0, TRUE, 0.0, 0.0);
        gtk_text_buffer_delete_mark(tbuf, mark);
    }
}

static void sendMessage(GtkWidget* w, gpointer) {
    // echo 'me:' in UI
    char* tags[] = {"self", NULL};
    tsappend("me: ", tags, 0);

    // grab plaintext
    GtkTextIter s, e;
    gtk_text_buffer_get_start_iter(mbuf, &s);
    gtk_text_buffer_get_end_iter(mbuf, &e);
    gchar* message =
      gtk_text_buffer_get_text(mbuf, &s, &e, TRUE);
    size_t len = g_utf8_strlen(message, -1);

    // send via session API (does AES+HMAC+seq internally)
    session_send(sess,
      (const unsigned char*)message, len);

    // echo message in transcript
    tsappend(message, NULL, 1);

    // cleanup
    gtk_text_buffer_delete(mbuf, &s, &e);
    free(message);
}

static gboolean shownewmessage(gpointer data) {
    unsigned char* msg = data;
    char* tags[] = {"friend", NULL};
    tsappend("friend: ", tags, 0);
    tsappend((char*)msg, NULL, 1);
    free(msg);
    return FALSE;
}

int main(int argc, char* argv[]) {
    // load DH params
    if (init("params") != 0) {
        fprintf(stderr,
                "could not read DH params\n");
        return 1;
    }

    // parse CLI
    static struct option opts[] = {
        {"connect", required_argument, 0, 'c'},
        {"listen",  no_argument,       0, 'l'},
        {"port",    required_argument, 0, 'p'},
        {"identity",required_argument, 0, 'i'},
        {"peer",    required_argument, 0, 'e'},
        {"help",    no_argument,       0, 'h'},
        {0,0,0,0}
    };
    int opt, port = 1337;
    char host[HOST_NAME_MAX+1] = "localhost";
    char* mykey  = NULL;
    char* peerkey= NULL;
    while ((opt = getopt_long(argc, argv,
               "c:lp:i:e:h", opts, NULL)) != -1) {
        switch(opt) {
            case 'c':
                strncpy(host, optarg,
                        HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'i':
                mykey = optarg;
                break;
            case 'e':
                peerkey = optarg;
                break;
            case 'h':
                printf("Usage: chat [-l] [-c host]"
                       " [-p port] [-i idfile]"
                       " [-e peerfile]\n");
                return 0;
        }
    }

    // connect or listen
    if (isclient)
        initClientNet(host, port);
    else
        initServerNet(port);

    // mutual‐auth + key‐derivation
    sess = session_create(sockfd, mykey, peerkey);
    if (!sess) {
        fprintf(stderr, "handshake failed\n");
        return 1;
    }

    // GTK/UI setup (unchanged)
    gtk_init(&argc, &argv);
    GError* err = NULL;
    GtkBuilder* builder =
      gtk_builder_new();
    if (!gtk_builder_add_from_file(
          builder, "layout.ui", &err)) {
        g_printerr("Error loading UI: %s\n",
                   err->message);
        return 1;
    }

    mark  = gtk_text_mark_new(NULL, TRUE);
    tview = GTK_TEXT_VIEW(
      gtk_builder_get_object(builder,
                             "transcript"));
    mbuf  = gtk_text_view_get_buffer(
      GTK_TEXT_VIEW(
        gtk_builder_get_object(builder,
                               "message")));
    tbuf  = gtk_text_view_get_buffer(tview);

    gtk_builder_connect_signals(builder, NULL);
    GtkWidget* window =
      GTK_WIDGET(
        gtk_builder_get_object(builder,
                               "window"));
    GtkWidget* send_btn =
      GTK_WIDGET(
        gtk_builder_get_object(builder,
                               "send"));
    g_signal_connect(send_btn,
      "clicked", G_CALLBACK(sendMessage),
      NULL);
    gtk_widget_show_all(window);

    // start receiver thread
    pthread_create(&trecv, NULL,
                   recvMsg, NULL);

    // enter GTK loop
    gtk_main();

    shutdownNetwork();
    session_destroy(sess);
    return 0;
}

// background thread: unwrap session_recv() → display
void* recvMsg(void* d) {
    while (1) {
        unsigned char* buf = NULL;
        size_t len = 0;
        if (session_recv(sess, &buf, &len) != 0)
            break;
        buf[len] = '\0';
        g_idle_add(shownewmessage, buf);
    }
    return NULL;
}
