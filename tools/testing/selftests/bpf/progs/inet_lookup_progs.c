// SPDX-License-Identifier: GPL-2.0
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

enum {
	SERVER_A = 0,
	SERVER_B = 1,
};

enum {
	NO_FLAGS = 0,
};

static const __u32 DST_PORT = 7007;
static const __u32 DST_IP4 = IP4(127, 0, 0, 1);
static const __u32 DST_IP6[] = IP6(0xfd000000, 0x0, 0x0, 0x00000001);

SEC("inet_lookup/no_redir")
int no_redir(struct bpf_inet_lookup *ctx)
{
	return BPF_OK;
}

/* Redirect packets destined for port DST_PORT to socket at redir_map[0]. */
SEC("inet_lookup/redir_port")
int redir_port(struct bpf_inet_lookup *ctx)
{
	__u32 key = SERVER_A;

	if (ctx->local_port != DST_PORT)
		return BPF_OK;

	return bpf_redirect_lookup(ctx, &redir_map, &key, NO_FLAGS);
}

/* Redirect packets destined for DST_IP4 address to socket at redir_map[0]. */
SEC("inet_lookup/redir_ip4")
int redir_ip4(struct bpf_inet_lookup *ctx)
{
	__u32 key = SERVER_A;

	if (ctx->family != AF_INET)
		return BPF_OK;
	if (ctx->local_port != DST_PORT)
		return BPF_OK;
	if (ctx->local_ip4 != DST_IP4)
		return BPF_OK;

	return bpf_redirect_lookup(ctx, &redir_map, &key, NO_FLAGS);
}

/* Redirect packets destined for DST_IP6 address to socket at redir_map[0]. */
SEC("inet_lookup/redir_ip6")
int redir_ip6(struct bpf_inet_lookup *ctx)
{
	__u32 key = SERVER_A;

	if (ctx->family != AF_INET6)
		return BPF_OK;
	if (ctx->local_port != DST_PORT)
		return BPF_OK;
	if (ctx->local_ip6[0] != DST_IP6[0] ||
	    ctx->local_ip6[1] != DST_IP6[1] ||
	    ctx->local_ip6[2] != DST_IP6[2] ||
	    ctx->local_ip6[3] != DST_IP6[3])
		return BPF_OK;

	return bpf_redirect_lookup(ctx, &redir_map, &key, NO_FLAGS);
}

SEC("inet_lookup/select_sock_a")
int select_sock_a(struct bpf_inet_lookup *ctx)
{
	__u32 key = SERVER_A;

	return bpf_redirect_lookup(ctx, &redir_map, &key, NO_FLAGS);
}

SEC("sk_reuseport/select_sock_b")
int select_sock_b(struct sk_reuseport_md *ctx)
{
	__u32 key = SERVER_B;
	int err;

	err = bpf_sk_select_reuseport(ctx, &redir_map, &key, NO_FLAGS);
	return err ? SK_DROP : SK_PASS;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
