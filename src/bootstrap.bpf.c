// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "bootstrap.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define IP_ADDRESS(x) (unsigned int)(127 + (0 << 8) + (0 << 16) + (1 << 24))
#define ETH_P_IP 0x0800

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void*) (long)ctx->data;

	bpf_printk("Check if we got a packet");
	
	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
	{
		bpf_printk("Invalid ethhdr size\n");
		return XDP_ABORTED;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
	{
		bpf_printk("Not an IP packet\n");
		return XDP_PASS;
	}

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		bpf_printk("Invalid iphdr size\n");
		return XDP_ABORTED;
	}

	if ((iph->protocol) != IPPROTO_TCP)
	{
		bpf_printk("Not a TCP packet\n");
		return XDP_PASS;
	}

	bpf_printk("got packet from %x", iph->saddr);

	//I'M COMMENTING OUT THIS CODE BECAUSE IT'S USED FOR LOAD BALANCING
	//WHICH ISN'T MY GOAL ATM

	// if (iph->saddr == IP_ADDRESS(CLIENT))
	// {
	// 	char backend = BACKEND_1;
	// 	if (bpf_ktime_get_ns() % 2)
	// 	{
	// 		backend = BACKEND_2;
	// 	}
	// 	iph->daddr = IP_ADDRESS(backend);
	// 	eth->h_dest[5] = backend;
	// }
	// else
	// {
	// 	iph->daddr = IP_ADDRESS(CLIENT);
	// 	eth->h_dest[5] = CLIENT;
	// }

	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
	{
		bpf_printk("ringbuf reserve failed\n");
		return XDP_ABORTED;
	}

	e->time = bpf_ktime_get_ns();
	bpf_ringbuf_submit(e, 0);

	return XDP_PASS;
}