#ifndef __BOOTSTRAP_BPF_H
#define __BOOTSTRAP_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct event {
    unsigned long long time;
};

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

#endif /* __BOOTSTRAP_BPF_H */
