/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#include "linux/in6.h"

#ifndef __LINUX_IN6_H
#define __LINUX_IN6_H
#endif

typedef union {
    __be32 ipv4;
    struct in6_addr ipv6;
} ip_address;

struct flow {
    ip_address src_addr;
    ip_address dst_addr;
    __be16 src_port;
    __be16 dst_port;
    __be16 l3_proto;
    __u8 l4_proto;
};

#endif /* __BOOTSTRAP_H */
