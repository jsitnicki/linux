// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skbuff.h>

DEFINE_BPF_STORAGE_CACHE(skb_cache);

static int notsupp_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -EOPNOTSUPP;
}

static void *notsupp_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static long notsupp_update_elem(struct bpf_map *map, void *key,
				void *value, u64 flags)
{
	return -EOPNOTSUPP;
}

static long notsupp_delete_elem(struct bpf_map *map, void *key)
{
	return -EOPNOTSUPP;
}

static struct bpf_map *skb_storage_map_alloc(union bpf_attr *attr)
{
	return bpf_local_storage_map_alloc(attr, &skb_cache, true);
}

static void skb_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &skb_cache, NULL);
}

const struct bpf_map_ops skb_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = skb_storage_map_alloc,
	.map_free = skb_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = notsupp_lookup_elem,
	.map_update_elem = notsupp_update_elem,
	.map_delete_elem = notsupp_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
};

__bpf_kfunc_start_defs();

/**
 * bpf_skb_storage_get() - Get or create local storage for an skb
 * @map: BPF map of type BPF_MAP_TYPE_SKB_STORAGE
 * @skb: Socket buffer to get storage for
 * @value: Initial value to set if creating new storage (can be NULL)
 * @flags: BPF_LOCAL_STORAGE_GET_F_CREATE to create if not exists
 *
 * Get the local storage associated with @skb for @map. If @flags contains
 * BPF_LOCAL_STORAGE_GET_F_CREATE and no storage exists, create new storage
 * initialized with @value (or zeroed if @value is NULL).
 *
 * Return: Pointer to storage value on success, NULL on error
 */
__bpf_kfunc void *bpf_skb_storage_get(struct bpf_map *map, struct sk_buff *skb,
				      void *value, u64 flags)
{
	return NULL;
}

/**
 * bpf_skb_storage_delete() - Delete local storage for an skb
 * @map: BPF map of type BPF_MAP_TYPE_SKB_STORAGE
 * @skb: Socket buffer to delete storage from
 *
 * Delete the local storage associated with @skb for @map.
 *
 * Return: 0 on success, negative error code on failure
 */
__bpf_kfunc int bpf_skb_storage_delete(struct bpf_map *map, struct sk_buff *skb)
{
	return -EOPNOTSUPP;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_skb_storage_kfunc_ids)
BTF_ID_FLAGS(func, bpf_skb_storage_get, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_skb_storage_delete)
BTF_KFUNCS_END(bpf_skb_storage_kfunc_ids)

static const struct btf_kfunc_id_set bpf_skb_storage_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_skb_storage_kfunc_ids,
};

static int __init bpf_skb_storage_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					&bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_ACT,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SK_SKB,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCKET_FILTER,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_CGROUP_SKB,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_OUT,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_IN,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_XMIT,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_LWT_SEG6LOCAL,
					       &bpf_skb_storage_kfunc_set);
	ret = ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_NETFILTER,
					       &bpf_skb_storage_kfunc_set);
	return ret;
}
late_initcall(bpf_skb_storage_kfunc_init);
