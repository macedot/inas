/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#include "DiscoveryUDP.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int inas_udp_open(const char *iface_ip, uint16_t local_port, const char *mcast_group,
                  int join_group)
{
        int fd;
        int yes = 1;
        struct sockaddr_in addr;
        struct in_addr iface;
        unsigned char ttl = 1;
        unsigned char loop = 0;

        if (!iface_ip) {
                return -EINVAL;
        }
        if (inet_pton(AF_INET, iface_ip, &iface) != 1) {
                return -EINVAL;
        }

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0) {
                return -errno;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
        (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &iface, sizeof(iface));
        (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        (void)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(local_port);
        addr.sin_addr = iface;
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                int err = errno;
                close(fd);
                return -err;
        }

        if (join_group && mcast_group) {
                struct ip_mreq mreq;
                memset(&mreq, 0, sizeof(mreq));
                if (inet_pton(AF_INET, mcast_group, &mreq.imr_multiaddr) == 1) {
                        mreq.imr_interface = iface;
                        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
                                       sizeof(mreq)) != 0) {
                                int err = errno;
                                /* iOS drops multicast without the
                                 * com.apple.developer.networking.multicast
                                 * entitlement - surface it instead of
                                 * leaving the responder deaf. */
                                fprintf(stderr, "inas-udp: join %s failed: %s\n", mcast_group,
                                        strerror(err));
                                close(fd);
                                return -err;
                        }
                }
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
                (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        return fd;
}

int inas_udp_sendto(int fd, const char *dst_ip, uint16_t dst_port, const void *data, int len)
{
        struct sockaddr_in addr;
        ssize_t n;

        if (fd < 0 || !dst_ip || !data || len <= 0) {
                return -EINVAL;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(dst_port);
        if (inet_pton(AF_INET, dst_ip, &addr.sin_addr) != 1) {
                return -EINVAL;
        }
        n = sendto(fd, data, (size_t)len, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (n < 0) {
                return -errno;
        }
        return (int)n;
}

int inas_udp_recvfrom(int fd, void *buf, int buflen, char *src_ip, int src_ip_len,
                      uint16_t *src_port)
{
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        ssize_t n;

        if (fd < 0 || !buf || buflen <= 0) {
                return -EINVAL;
        }
        memset(&addr, 0, sizeof(addr));
        n = recvfrom(fd, buf, (size_t)buflen, 0, (struct sockaddr *)&addr, &alen);
        if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return 0;
                }
                return -errno;
        }
        if (src_ip && src_ip_len > 0) {
                inet_ntop(AF_INET, &addr.sin_addr, src_ip, (socklen_t)src_ip_len);
        }
        if (src_port) {
                *src_port = ntohs(addr.sin_port);
        }
        return (int)n;
}

void inas_udp_close(int fd)
{
        if (fd >= 0) {
                close(fd);
        }
}
