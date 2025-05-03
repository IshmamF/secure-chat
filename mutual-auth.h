#ifndef MUTUAL_AUTH_H
#define MUTUAL_AUTH_H

#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Perform mutual authentication over an established socket after a DH exchange.
 *
 * @param my_privkey_file     Path to our PEM-encoded private key file.
 * @param peer_pubkey_file    Path to peer's PEM-encoded public key file.
 * @param my_pub              Pointer to our ephemeral DH public bytes.
 * @param my_pub_len          Length of our ephemeral public key in bytes.
 * @param peer_pub            Pointer to peer's ephemeral DH public bytes.
 * @param peer_pub_len        Length of peer's ephemeral public key in bytes.
 * @param sockfd              Connected socket file descriptor.
 * @return                    1 on successful mutual authentication, 0 on failure.
 */
int mutual_authenticate(const char*        my_privkey_file,
                        const char*        peer_pubkey_file,
                        const unsigned char* my_pub, size_t my_pub_len,
                        const unsigned char* peer_pub, size_t peer_pub_len,
                        int sockfd);

#ifdef __cplusplus
}
#endif

#endif // MUTUAL_AUTH_H