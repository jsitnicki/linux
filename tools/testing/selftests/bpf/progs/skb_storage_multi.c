// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define MAGIC_VALUE 0xCAFEBABE

struct skb_stg {
	__u32 value;
	__u32 src_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
	__u8 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_SKB_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct skb_stg);
} skb_stg_map SEC(".maps");

volatile __u32 tc_ingress_seen = 0;
volatile __u32 tc_egress_seen = 0;
volatile __u32 cgroup_ingress_seen = 0;
volatile __u32 cgroup_egress_seen = 0;
volatile __u32 socket_filter_seen = 0;
volatile __u32 sock_ops_seen = 0;

volatile __u32 tc_ingress_value = 0;
volatile __u32 cgroup_ingress_value = 0;
volatile __u32 cgroup_egress_value = 0;
volatile __u32 socket_filter_value = 0;
volatile __u32 sock_ops_value = 0;

volatile __be16 target_port = 0;

enum layer { L2, L3, L4 };

static __always_inline int get_ports(struct __sk_buff *skb, __u16 *src,
				     __u16 *dst, enum layer layer)
{
	__u32 off = 0;
	__u8 ihl;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return -1;

	switch (layer) {
	case L2:
		off += ETH_HLEN;
		/* fallthrough; */
	case L3:
		if (bpf_skb_load_bytes(skb, off, &ihl, 1))
			return -1;
		off += (ihl & 0xf) * 4;
		/* fallthrough; */
	case L4:
		if (bpf_skb_load_bytes(skb, off, src, 2))
			return -1;
		if (bpf_skb_load_bytes(skb, off + 2, dst, 2))
			return -1;
	}

	return 0;
}

SEC("tc/ingress")
int tc_ingress_store(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;
	__u16 src, dst;

	if (get_ports(ctx, &src, &dst, L2))
		return TC_ACT_OK;

	if (dst != target_port && src != target_port)
		return TC_ACT_OK;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!stg)
		return TC_ACT_OK;

	stg->value = MAGIC_VALUE;
	stg->src_port = src;
	stg->dst_port = dst;
	tc_ingress_seen++;

	return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress_read(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;
	__u16 src, dst;

	if (get_ports(ctx, &src, &dst, L2))
		return TC_ACT_OK;

	if (dst != target_port && src != target_port)
		return TC_ACT_OK;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL, 0);
	if (stg)
		tc_egress_seen++;

	return TC_ACT_OK;
}

SEC("cgroup_skb/ingress")
int cgroup_ingress_read(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;
	__u16 src, dst;

	if (get_ports(ctx, &src, &dst, L3))
		return 1;

	if (dst != target_port && src != target_port)
		return 1;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL, 0);
	if (stg) {
		cgroup_ingress_seen++;
		cgroup_ingress_value = stg->value;
	}

	return 1;
}

SEC("cgroup_skb/egress")
int cgroup_egress_store(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;
	__u16 src, dst;

	if (get_ports(ctx, &src, &dst, L3))
		return 1;

	if (dst != target_port && src != target_port)
		return 1;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (stg) {
		stg->value = MAGIC_VALUE;
		stg->src_port = src;
		stg->dst_port = dst;
		cgroup_egress_seen++;
		cgroup_egress_value = stg->value;
	}

	return 1;
}

SEC("socket")
int socket_filter_read(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;
	__u16 src, dst;

	if (get_ports(ctx, &src, &dst, L4))
		goto out;

	if (dst != target_port && src != target_port)
		goto out;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL, 0);
	if (stg) {
		socket_filter_seen++;
		socket_filter_value = stg->value;
	}
out:
	return ctx->len;
}

SEC("sockops")
int sockops_read(struct bpf_sock_ops *ctx)
{
	struct sk_buff *skb;
	struct skb_stg *stg;

	if (ctx->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
		return 1;

	if (ctx->local_port != bpf_ntohs(target_port) && ctx->remote_port != target_port)
		return 1;

	skb = bpf_sock_ops_skb(ctx);
	if (!skb)
		return 1;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL, 0);
	if (stg) {
		sock_ops_seen++;
		sock_ops_value = stg->value;
	}

	return 1;
}
