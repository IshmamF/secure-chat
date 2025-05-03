#ifndef MUTUAL_AUTH_H
#define MUTUAL_AUTH_H

#include <stddef.h>
#include <stdint.h>

/**
 * After your ephemeral DH, do mutual authentication:
 *
 * @param my_privkey_file     path to your long‑term private key (PEM)
 * @param peer_pubkey_file    path to peer’s long‑term public key (PEM)
 * @param my_pub              your ephemeral public‐key bytes
 * @param my_pub_len          length of my_pub in bytes
 * @param peer_pub            peer’s ephemeral public‐key bytes
 * @param peer_pub_len        length of peer_pub in bytes
 * @param sockfd              connected socket FD
 * @param is_client           nonzero if this side is the client
 * @return                    1 on success, 0 on failure
 */
int mutual_authenticate(const char*            my_privkey_file,
                        const char*            peer_pubkey_file,
                        const unsigned char*   my_pub,     size_t my_pub_len,
                        const unsigned char*   peer_pub,   size_t peer_pub_len,
                        int                     sockfd,
                        int                     is_client);

#endif 
