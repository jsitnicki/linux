// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#include <test_progs.h>
#include <network_helpers.h>
#include "skb_local_storage.skel.h"

#define IFINDEX_LO 1
#define MAGIC_VALUE 0xdeadbeef

static void test_skb_storage_get(void)
{
	struct skb_local_storage *skel;
	struct bpf_link *link;

	skel = skb_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	link = bpf_program__attach_tcx(skel->progs.skb_storage_get_test,
				       IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(link, "tcx_attach"))
		goto cleanup;

	skel->data->get_result = -1;
	skel->bss->pkt_count = 0;

	ASSERT_OK(SYS_NOFAIL("ping -c 1 -W 1 127.0.0.1 > /dev/null"), "ping");

	ASSERT_EQ(skel->data->get_result, 0, "get_result");
	ASSERT_GT(skel->bss->pkt_count, 0, "pkt_count");

	bpf_link__destroy(link);
cleanup:
	skb_local_storage__destroy(skel);
}

static void test_skb_storage_delete(void)
{
	struct skb_local_storage *skel;
	struct bpf_link *link;

	skel = skb_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	link = bpf_program__attach_tcx(skel->progs.skb_storage_delete_test,
				       IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(link, "tcx_attach"))
		goto cleanup;

	skel->data->delete_result = -1;

	ASSERT_OK(SYS_NOFAIL("ping -c 1 -W 1 127.0.0.1 > /dev/null"), "ping");

	ASSERT_EQ(skel->data->delete_result, 0, "delete_result");

	bpf_link__destroy(link);
cleanup:
	skb_local_storage__destroy(skel);
}

static void test_skb_storage_clone(void)
{
	struct skb_local_storage *skel;
	struct bpf_link *link;

	skel = skb_local_storage__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		return;

	link = bpf_program__attach_tcx(skel->progs.skb_storage_clone_test,
				       IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(link, "tcx_attach"))
		goto cleanup;

	skel->data->get_result = -1;
	skel->bss->pkt_count = 0;

	ASSERT_OK(SYS_NOFAIL("ping -c 1 -W 1 127.0.0.1 > /dev/null"), "ping");

	ASSERT_EQ(skel->data->get_result, 0, "get_result");
	ASSERT_GT(skel->bss->pkt_count, 0, "pkt_count");

	bpf_link__destroy(link);
cleanup:
	skb_local_storage__destroy(skel);
}

void test_skb_local_storage(void)
{
	if (test__start_subtest("skb_storage_get"))
		test_skb_storage_get();
	if (test__start_subtest("skb_storage_delete"))
		test_skb_storage_delete();
	if (test__start_subtest("skb_storage_clone"))
		test_skb_storage_clone();
}
