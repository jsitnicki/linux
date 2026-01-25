/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Cloudflare, Inc. */

#ifndef _BPF_SKB_STORAGE_H
#define _BPF_SKB_STORAGE_H

struct bpf_local_storage;

#ifdef CONFIG_BPF_SKB_STORAGE
void bpf_skb_storage_free(struct bpf_local_storage *storage);
#else
static inline void bpf_skb_storage_free(struct bpf_local_storage *storage) {}
#endif

#endif /* _BPF_SKB_STORAGE_H */
