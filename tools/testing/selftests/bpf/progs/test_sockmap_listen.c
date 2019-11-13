// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Cloudflare

#include <errno.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, unsigned int);
} verdict_map SEC(".maps");

SEC("sk_skb/stream_parser")
int prog_skb_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int prog_skb_verdict(struct __sk_buff *skb)
{
	unsigned int *count;
	int verdict;

	verdict = bpf_sk_redirect_map(skb, &sock_map, 0, 0);

	count = bpf_map_lookup_elem(&verdict_map, &verdict);
	if (count)
		(*count)++;

	return verdict;
}

SEC("sk_msg")
int prog_msg_verdict(struct sk_msg_md *msg)
{
	unsigned int *count;
	int verdict;

	verdict = bpf_msg_redirect_map(msg, &sock_map, 0, 0);

	count = bpf_map_lookup_elem(&verdict_map, &verdict);
	if (count)
		(*count)++;

	return verdict;
}

SEC("sk_reuseport")
int prog_reuseport(struct sk_reuseport_md *reuse)
{
	unsigned int *count;
	int err, verdict;
	int key = 0;

	err = bpf_sk_select_reuseport(reuse, &sock_map, &key, 0);
	verdict = (!err || err == -ENOENT) ? SK_PASS : SK_DROP;

	count = bpf_map_lookup_elem(&verdict_map, &verdict);
	if (count)
		(*count)++;

	return verdict;
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
