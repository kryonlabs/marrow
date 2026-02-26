/*
 * Marrow - Platform Socket Abstraction
 * C89/C90 compliant
 */

#ifndef PLATFORM_SOCKET_H
#define PLATFORM_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

/*
 * Listen on a TCP port (IPv6 dual-stack for IPv4+IPv6)
 * Returns socket fd on success, -1 on failure
 */
int tcp_listen(int port);

/*
 * Accept a new connection
 * Returns client fd on success, -1 on failure
 */
int tcp_accept(int listen_fd);

/*
 * Close a connection
 */
void tcp_close(int fd);

/*
 * Receive a 9P message (with length prefix)
 * Returns message length on success, 0 if no data, -1 on error
 */
int tcp_recv_msg(int fd, unsigned char *buf, size_t buf_size);

/*
 * Send a 9P message (with length prefix)
 * Returns 0 on success, -1 on error
 */
int tcp_send_msg(int fd, const unsigned char *buf, size_t msg_len);

#endif /* PLATFORM_SOCKET_H */
