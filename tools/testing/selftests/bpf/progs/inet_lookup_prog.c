// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <sys/socket.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

#define IP4(a, b, c, d)	((__u32)(		\
	((__u32)((a) & (__u32)0xffUL) << 24) |	\
	((__u32)((b) & (__u32)0xffUL) << 16) |	\
	((__u32)((c) & (__u32)0xffUL) <<  8) |	\
	((__u32)((d) & (__u32)0xffUL) <<  0)))

#define REUSEPORT_ARRAY_SIZE 32

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, REUSEPORT_ARRAY_SIZE);
	__type(key, __u32);
	__type(value, __u64);
} redir_map SEC(".maps");

static const __u32 DST_PORT = 7007;
static const __u32 DST_IP4 = IP4(127, 0, 0, 1);
static const __u32 DST_IP6[] = { 0xfd000000, 0x0, 0x0, 0x00000001 };

/* Redirect packets destined for port DST_PORT to socket at redir_map[0]. */
SEC("inet_lookup/redir_port")
int inet4_remap_port(struct bpf_inet_lookup *ctx)
{
	__u32 index = 0;
	__u64 flags = 0;

	if (ctx->local_port != DST_PORT)
		return BPF_OK;

	return bpf_redirect_lookup(ctx, &redir_map, &index, flags);
}

/* Redirect packets destined for DST_IP4 address to socket at redir_map[0]. */
SEC("inet_lookup/redir_ip4")
int inet4_remap_ip(struct bpf_inet_lookup *ctx)
{
	__u32 index = 0;
	__u64 flags = 0;

	if (ctx->family != AF_INET)
		return BPF_OK;
	if (ctx->local_port != DST_PORT)
		return BPF_OK;
	if (ctx->local_ip4 != bpf_htonl(DST_IP4))
		return BPF_OK;

	return bpf_redirect_lookup(ctx, &redir_map, &index, flags);
}

/* Redirect packets destined for DST_IP6 address to socket at redir_map[0]. */
SEC("inet_lookup/redir_ip6")
int inet6_remap_ip(struct bpf_inet_lookup *ctx)
{
	__u32 index = 0;
	__u64 flags = 0;

	if (ctx->family != AF_INET6)
		return BPF_OK;
	if (ctx->local_port != DST_PORT)
		return BPF_OK;
	if (ctx->local_ip6[0] != bpf_htonl(DST_IP6[0]) ||
	    ctx->local_ip6[1] != bpf_htonl(DST_IP6[1]) ||
	    ctx->local_ip6[2] != bpf_htonl(DST_IP6[2]) ||
	    ctx->local_ip6[3] != bpf_htonl(DST_IP6[3]))
		return BPF_OK;

	return bpf_redirect_lookup(ctx, &redir_map, &index, flags);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
