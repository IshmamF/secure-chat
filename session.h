#pragma once
#include <gmp.h>
#include <stdint.h>

/** Opaque session object encapsulating keys, counters, and cipher state */
typedef struct Session Session;

/** Perform the DH handshake, derive AES & HMAC keys, and return a new Session. */
Session* session_create(int sockfd,
                        const char* my_privkey_file,
                        const char* peer_pubkey_file);

/** Encrypt+MAC+send a buffer of plain text */
int session_send(Session* s, const unsigned char* pt, size_t ptlen);

/** Receive+verify+decrypt one message.  Caller gets a malloc’d buffer. */
int session_recv(Session* s, unsigned char** out, size_t* outlen);

/** Clean up all secrets & free the Session */
void session_destroy(Session* s);