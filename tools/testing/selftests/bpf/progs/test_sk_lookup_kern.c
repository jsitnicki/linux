// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2020 Cloudflare

#include <errno.h>
#include <linux/bpf.h>
#include <sys/socket.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define IP4(a, b, c, d)					\
	bpf_htonl((((__u32)(a) & 0xffU) << 24) |	\
		  (((__u32)(b) & 0xffU) << 16) |	\
		  (((__u32)(c) & 0xffU) <<  8) |	\
		  (((__u32)(d) & 0xffU) <<  0))
#define IP6(aaaa, bbbb, cccc, dddd)			\
	{ bpf_htonl(aaaa), bpf_htonl(bbbb), bpf_htonl(cccc), bpf_htonl(dddd) }

#define MAX_SOCKS 32

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, MAX_SOCKS);
	__type(key, __u32);
	__type(value, __u64);
} redir_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} run_map SEC(".maps");

enum {
	PROG1 = 0,
	PROG2,
};

enum {
	SERVER_A = 0,
	SERVER_B,
};

/* Addressable key/value constants for convenience */
static const int KEY_PROG1 = PROG1;
static const int KEY_PROG2 = PROG2;
static const int PROG_DONE = 1;

static const __u32 KEY_SERVER_A = SERVER_A;
static const __u32 KEY_SERVER_B = SERVER_B;

static const __u32 DST_PORT = 7007;
static const __u32 DST_IP4 = IP4(127, 0, 0, 1);
static const __u32 DST_IP6[] = IP6(0xfd000000, 0x0, 0x0, 0x00000001);

SEC("sk_lookup/lookup_pass")
int lookup_pass(struct bpf_sk_lookup *ctx)
{
	return BPF_OK;
}

SEC("sk_lookup/lookup_drop")
int lookup_drop(struct bpf_sk_lookup *ctx)
{
	return BPF_DROP;
}

SEC("sk_reuseport/reuse_pass")
int reuseport_pass(struct sk_reuseport_md *ctx)
{
	return SK_PASS;
}

SEC("sk_reuseport/reuse_drop")
int reuseport_drop(struct sk_reuseport_md *ctx)
{
	return SK_DROP;
}

/* Redirect packets destined for port DST_PORT to socket at redir_map[0]. */
SEC("sk_lookup/redir_port")
int redir_port(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	if (ctx->local_port != DST_PORT)
		return BPF_OK;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_OK;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? BPF_DROP : BPF_REDIRECT;
}

/* Redirect packets destined for DST_IP4 address to socket at redir_map[0]. */
SEC("sk_lookup/redir_ip4")
int redir_ip4(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	if (ctx->family != AF_INET)
		return BPF_OK;
	if (ctx->local_port != DST_PORT)
		return BPF_OK;
	if (ctx->local_ip4 != DST_IP4)
		return BPF_OK;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_OK;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? BPF_DROP : BPF_REDIRECT;
}

/* Redirect packets destined for DST_IP6 address to socket at redir_map[0]. */
SEC("sk_lookup/redir_ip6")
int redir_ip6(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	if (ctx->family != AF_INET6)
		return BPF_OK;
	if (ctx->local_port != DST_PORT)
		return BPF_OK;
	if (ctx->local_ip6[0] != DST_IP6[0] ||
	    ctx->local_ip6[1] != DST_IP6[1] ||
	    ctx->local_ip6[2] != DST_IP6[2] ||
	    ctx->local_ip6[3] != DST_IP6[3])
		return BPF_OK;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_OK;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? BPF_DROP : BPF_REDIRECT;
}

SEC("sk_lookup/select_sock_a")
int select_sock_a(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_OK;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? BPF_DROP : BPF_REDIRECT;
}

SEC("sk_lookup/select_sock_a_no_reuseport")
int select_sock_a_no_reuseport(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_DROP;

	err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_NO_REUSEPORT);
	bpf_sk_release(sk);
	return err ? BPF_DROP : BPF_REDIRECT;
}

SEC("sk_reuseport/select_sock_b")
int select_sock_b(struct sk_reuseport_md *ctx)
{
	__u32 key = KEY_SERVER_B;
	int err;

	err = bpf_sk_select_reuseport(ctx, &redir_map, &key, 0);
	return err ? SK_DROP : SK_PASS;
}

/* Check that bpf_sk_assign() returns -EEXIST if socket already selected. */
SEC("sk_lookup/sk_assign_eexist")
int sk_assign_eexist(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err, ret;

	ret = BPF_DROP;
	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
	if (!sk)
		goto out;
	err = bpf_sk_assign(ctx, sk, 0);
	if (err)
		goto out;
	bpf_sk_release(sk);

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		goto out;
	err = bpf_sk_assign(ctx, sk, 0);
	if (err != -EEXIST) {
		bpf_printk("sk_assign returned %d, expected %d\n",
			   err, -EEXIST);
		goto out;
	}

	ret = BPF_REDIRECT; /* Success, redirect to KEY_SERVER_B */
out:
	if (sk)
		bpf_sk_release(sk);
	return ret;
}

/* Check that bpf_sk_assign(BPF_SK_LOOKUP_F_REPLACE) can override selection. */
SEC("sk_lookup/sk_assign_replace_flag")
int sk_assign_replace_flag(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err, ret;

	ret = BPF_DROP;
	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		goto out;
	err = bpf_sk_assign(ctx, sk, 0);
	if (err)
		goto out;
	bpf_sk_release(sk);

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
	if (!sk)
		goto out;
	err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
	if (err) {
		bpf_printk("sk_assign returned %d, expected 0\n", err);
		goto out;
	}

	ret = BPF_REDIRECT; /* Success, redirect to KEY_SERVER_B */
out:
	if (sk)
		bpf_sk_release(sk);
	return ret;
}

/* Check that selected sk is accessible thru context. */
SEC("sk_lookup/access_ctx_sk")
int access_ctx_sk(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err, ret;

	ret = BPF_DROP;
	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		goto out;
	err = bpf_sk_assign(ctx, sk, 0);
	if (err)
		goto out;
	if (sk != ctx->sk) {
		bpf_printk("expected ctx->sk == KEY_SERVER_A\n");
		goto out;
	}
	bpf_sk_release(sk);

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
	if (!sk)
		goto out;
	err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
	if (err)
		goto out;
	if (sk != ctx->sk) {
		bpf_printk("expected ctx->sk == KEY_SERVER_B\n");
		goto out;
	}

	ret = BPF_REDIRECT; /* Success, redirect to KEY_SERVER_B */
out:
	if (sk)
		bpf_sk_release(sk);
	return ret;
}

/* Check that sk_assign rejects KEY_SERVER_A socket with -ESOCKNOSUPPORT */
SEC("sk_lookup/sk_assign_esocknosupport")
int sk_assign_esocknosupport(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err, ret;

	ret = BPF_DROP;
	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		goto out;

	err = bpf_sk_assign(ctx, sk, 0);
	if (err != -ESOCKTNOSUPPORT) {
		bpf_printk("sk_assign returned %d, expected %d\n",
			   err, -ESOCKTNOSUPPORT);
		goto out;
	}

	ret = BPF_OK; /* Success, pass to regular lookup */
out:
	if (sk)
		bpf_sk_release(sk);
	return ret;
}

SEC("sk_lookup/multi_prog_pass1")
int multi_prog_pass1(struct bpf_sk_lookup *ctx)
{
	bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
	return BPF_OK;
}

SEC("sk_lookup/multi_prog_pass2")
int multi_prog_pass2(struct bpf_sk_lookup *ctx)
{
	bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
	return BPF_OK;
}

SEC("sk_lookup/multi_prog_drop1")
int multi_prog_drop1(struct bpf_sk_lookup *ctx)
{
	bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
	return BPF_DROP;
}

SEC("sk_lookup/multi_prog_drop2")
int multi_prog_drop2(struct bpf_sk_lookup *ctx)
{
	bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
	return BPF_DROP;
}

SEC("sk_lookup/multi_prog_inval1")
int multi_prog_inval1(struct bpf_sk_lookup *ctx)
{
	bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
	return -1;
}

SEC("sk_lookup/multi_prog_inval2")
int multi_prog_inval2(struct bpf_sk_lookup *ctx)
{
	bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
	return -1;
}

SEC("sk_lookup/multi_prog_redir1")
int multi_prog_redir1(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_DROP;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	if (err)
		return BPF_DROP;

	bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
	return BPF_REDIRECT;
}

SEC("sk_lookup/multi_prog_redir2")
int multi_prog_redir2(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
	if (!sk)
		return BPF_DROP;

	err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
	bpf_sk_release(sk);
	if (err)
		return BPF_DROP;

	bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
	return BPF_REDIRECT;
}

char _license[] SEC("license") = "Dual BSD/GPL";
__u32 _version SEC("version") = 1;
