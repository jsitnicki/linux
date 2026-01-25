// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define TC_ACT_OK 0
#define MAGIC_VALUE 0xdeadbeef

struct skb_stg {
	__u32 value;
	__u32 pkt_count;
};

struct {
	__uint(type, BPF_MAP_TYPE_SKB_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct skb_stg);
} skb_stg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SKB_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_CLONE);
	__type(key, int);
	__type(value, struct skb_stg);
} skb_stg_clone_map SEC(".maps");

volatile int get_result = -1;
volatile int delete_result = -1;
volatile int seen_value = 0;
volatile int pkt_count = 0;

SEC("tc/ingress")
int skb_storage_get_test(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!stg) {
		get_result = -1;
		return TC_ACT_OK;
	}

	stg->value = MAGIC_VALUE;
	stg->pkt_count = ++pkt_count;
	get_result = 0;

	return TC_ACT_OK;
}

SEC("tc/egress")
int skb_storage_read_test(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL, 0);
	if (!stg) {
		seen_value = 0;
		return TC_ACT_OK;
	}

	seen_value = stg->value;
	return TC_ACT_OK;
}

SEC("tc/ingress")
int skb_storage_delete_test(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!stg) {
		delete_result = -1;
		return TC_ACT_OK;
	}

	stg->value = MAGIC_VALUE;

	delete_result = bpf_skb_storage_delete((struct bpf_map *)&skb_stg_map, skb);

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_map, skb, NULL, 0);
	if (stg) {
		delete_result = -2;
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

SEC("tc/ingress")
int skb_storage_clone_test(struct __sk_buff *ctx)
{
	struct sk_buff *skb = (struct sk_buff *)ctx;
	struct skb_stg *stg;

	stg = bpf_skb_storage_get((struct bpf_map *)&skb_stg_clone_map, skb, NULL,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!stg) {
		get_result = -1;
		return TC_ACT_OK;
	}

	stg->value = MAGIC_VALUE;
	stg->pkt_count = ++pkt_count;
	get_result = 0;

	return TC_ACT_OK;
}
