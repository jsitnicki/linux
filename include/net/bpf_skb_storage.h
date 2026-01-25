/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Cloudflare, Inc. */

#ifndef _BPF_SKB_STORAGE_H
#define _BPF_SKB_STORAGE_H

struct bpf_local_storage;
struct sk_buff;

#ifdef CONFIG_BPF_SKB_STORAGE
void bpf_skb_storage_free(struct bpf_local_storage *storage);
int bpf_skb_storage_clone(const struct sk_buff *skb, struct sk_buff *newskb);
#else
static inline void bpf_skb_storage_free(struct bpf_local_storage *storage) {}
static inline int bpf_skb_storage_clone(const struct sk_buff *skb,
					struct sk_buff *newskb)
{
	return 0;
}
#endif

#endif /* _BPF_SKB_STORAGE_H */
