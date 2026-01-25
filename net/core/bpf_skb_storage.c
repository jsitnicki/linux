// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/skbuff.h>
#include <net/bpf_skb_storage.h>

DEFINE_BPF_STORAGE_CACHE(skb_cache);

static DEFINE_PER_CPU(int, bpf_skb_storage_busy);

static void bpf_skb_storage_unlock(void)
{
	this_cpu_dec(bpf_skb_storage_busy);
}

static bool bpf_skb_storage_trylock(void)
{
	cant_migrate();
	if (unlikely(this_cpu_inc_return(bpf_skb_storage_busy) != 1)) {
		this_cpu_dec(bpf_skb_storage_busy);
		return false;
	}
	return true;
}

static struct bpf_local_storage_data *
skb_storage_lookup(struct sk_buff *skb, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_skb_storage_ext *ext;
	struct bpf_local_storage *storage;
	struct bpf_local_storage_map *smap;

	ext = skb_ext_find(skb, SKB_EXT_BPF_STORAGE);
	if (!ext)
		return NULL;

	storage = rcu_dereference_check(ext->storage, bpf_rcu_lock_held());
	if (!storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(storage, smap, cacheit_lockit);
}

static int skb_storage_delete(struct sk_buff *skb, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = skb_storage_lookup(skb, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata), false);
	return 0;
}

void bpf_skb_storage_free(struct bpf_local_storage *storage)
{
	bpf_local_storage_destroy(storage);
}

static struct bpf_local_storage_elem *
bpf_skb_storage_clone_elem(struct bpf_skb_storage_ext *new_ext,
			   struct bpf_local_storage_map *smap,
			   struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage_elem *copy_selem;

	copy_selem = bpf_selem_alloc(smap, new_ext, NULL, false, GFP_ATOMIC);
	if (!copy_selem)
		return NULL;

	if (btf_record_has_field(smap->map.record, BPF_SPIN_LOCK))
		copy_map_value_locked(&smap->map, SDATA(copy_selem)->data,
				      SDATA(selem)->data, true);
	else
		copy_map_value(&smap->map, SDATA(copy_selem)->data,
			       SDATA(selem)->data);

	return copy_selem;
}

int bpf_skb_storage_clone(const struct sk_buff *skb, struct sk_buff *newskb)
{
	struct bpf_local_storage *new_storage = NULL;
	struct bpf_local_storage *storage;
	struct bpf_local_storage_elem *selem;
	struct bpf_skb_storage_ext *ext, *new_ext;
	int ret = 0;

	ext = skb_ext_find(skb, SKB_EXT_BPF_STORAGE);
	if (!ext)
		return 0;

	rcu_read_lock();
	storage = rcu_dereference(ext->storage);
	if (!storage || hlist_empty(&storage->list)) {
		rcu_read_unlock();
		return 0;
	}

	new_ext = skb_ext_add(newskb, SKB_EXT_BPF_STORAGE);
	if (!new_ext) {
		rcu_read_unlock();
		return -ENOMEM;
	}
	new_ext->storage = NULL;

	hlist_for_each_entry_rcu(selem, &storage->list, snode) {
		struct bpf_local_storage_elem *copy_selem;
		struct bpf_local_storage_map *smap;
		struct bpf_map *map;

		smap = rcu_dereference(SDATA(selem)->smap);
		if (!(smap->map.map_flags & BPF_F_CLONE))
			continue;

		map = bpf_map_inc_not_zero(&smap->map);
		if (IS_ERR(map))
			continue;

		copy_selem = bpf_skb_storage_clone_elem(new_ext, smap, selem);
		if (!copy_selem) {
			ret = -ENOMEM;
			bpf_map_put(map);
			goto out;
		}

		if (new_storage) {
			bpf_selem_link_map(smap, copy_selem);
			bpf_selem_link_storage_nolock(new_storage, copy_selem);
		} else {
			ret = bpf_local_storage_alloc(new_ext, smap, copy_selem,
						      GFP_ATOMIC);
			if (ret) {
				bpf_selem_free(copy_selem, true);
				bpf_map_put(map);
				goto out;
			}
			new_storage = rcu_dereference(copy_selem->local_storage);
		}
		bpf_map_put(map);
	}

out:
	rcu_read_unlock();
	return ret;
}

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
	bpf_local_storage_map_free(map, &skb_cache, &bpf_skb_storage_busy);
}

static struct bpf_local_storage __rcu **bpf_skb_storage_ptr(void *owner)
{
	struct bpf_skb_storage_ext *ext = owner;

	return &ext->storage;
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
	.map_owner_storage_ptr = bpf_skb_storage_ptr,
	.map_local_storage_charge = NULL, /* TODO */
	.map_local_storage_uncharge = NULL, /* TODO */
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
__bpf_kfunc void *bpf_skb_storage_get(struct bpf_map *map__map, struct sk_buff *skb,
				      void *value__nullable, u64 flags)
{
	struct bpf_local_storage_data *sdata;
	struct bpf_skb_storage_ext *ext;
	bool nobusy;

	/* TODO: Check that map is actually BPF_SKB_LOCAL_STORAGE_MAP */

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~BPF_LOCAL_STORAGE_GET_F_CREATE || !skb)
		return NULL;

	nobusy = bpf_skb_storage_trylock();

	sdata = skb_storage_lookup(skb, map__map, nobusy);
	if (sdata) {
		if (nobusy)
			bpf_skb_storage_unlock();
		return sdata->data;
	}

	if (!(flags & BPF_LOCAL_STORAGE_GET_F_CREATE) || !nobusy) {
		if (nobusy)
			bpf_skb_storage_unlock();
		return NULL;
	}

	/* Allocate the skb_ext if it doesn't exist yet */
	ext = skb_ext_find(skb, SKB_EXT_BPF_STORAGE);
	if (!ext) {
		ext = skb_ext_add(skb, SKB_EXT_BPF_STORAGE);
		if (!ext) {
			bpf_skb_storage_unlock();
			return NULL;
		}
		ext->storage = NULL;
	}

	sdata = bpf_local_storage_update(ext,
					 (struct bpf_local_storage_map *)map__map,
					 value__nullable,
					 BPF_NOEXIST, false, GFP_ATOMIC);
	bpf_skb_storage_unlock();

	return IS_ERR(sdata) ? NULL : sdata->data;
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
	int ret;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!skb)
		return -EINVAL;

	if (!bpf_skb_storage_trylock())
		return -EBUSY;

	ret = skb_storage_delete(skb, map);
	bpf_skb_storage_unlock();

	return ret;
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
