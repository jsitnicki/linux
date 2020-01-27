// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 Cloudflare Ltd https://cloudflare.com */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/skmsg.h>
#include <linux/wait.h>
#include <net/udp.h>

#include <net/inet_common.h>

static int udp_bpf_rebuild_protos(struct proto *prot, struct proto *base)
{
	*prot        = *base;
	prot->unhash = sock_map_unhash;
	prot->close  = sock_map_close;
	return 0;
}

static struct proto *udp_bpf_choose_proto(struct proto prot[],
					  struct sk_psock *psock)
{
	return prot;
}

static struct proto udpv4_proto;
static struct proto udpv6_proto;

static struct sk_psock_hooks udp_psock_proto __read_mostly = {
	.ipv4 = &udpv4_proto,
	.ipv6 = &udpv6_proto,
	.rebuild_proto = udp_bpf_rebuild_protos,
	.choose_proto = udp_bpf_choose_proto,
};

static int __init udp_bpf_init_psock_hooks(void)
{
	return sk_psock_hooks_init(&udp_psock_proto, &udp_prot);
}
core_initcall(udp_bpf_init_psock_hooks);

int udp_bpf_init(struct sock *sk)
{
	int ret;

	sock_owned_by_me(sk);

	rcu_read_lock();
	ret = sk_psock_hooks_install(&udp_psock_proto, sk);
	rcu_read_unlock();
	return ret;
}
