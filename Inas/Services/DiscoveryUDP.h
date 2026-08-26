/* Copyright (C) 2026 Thiago Macedo
 * SPDX-License-Identifier: AGPL-3.0-or-later */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UDP socket bound to iface_ip:local_port, multicast TTL 1, optional group join.
 * Returns fd >= 0, or -errno.
 */
int inas_udp_open(const char *iface_ip, uint16_t local_port, const char *mcast_group,
                  int join_group);

int inas_udp_sendto(int fd, const char *dst_ip, uint16_t dst_port, const void *data, int len);

/* Returns byte count, 0 if no packet, or -errno. */
int inas_udp_recvfrom(int fd, void *buf, int buflen, char *src_ip, int src_ip_len,
                      uint16_t *src_port);

void inas_udp_close(int fd);

#ifdef __cplusplus
}
#endif
