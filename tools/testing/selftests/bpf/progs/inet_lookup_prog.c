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

static const __u32 CONNECT_PORT = 7007;
static const __u32 LISTEN_PORT  = 8008;

static const __u32 CONNECT_IP4 = IP4(127, 0, 0, 1);
static const __u32 LISTEN_IP4  = IP4(127, 0, 0, 2);

/* Remap destination port CONNECT_PORT -> LISTEN_PORT. */
SEC("inet_lookup/remap_port")
int inet4_remap_port(struct bpf_inet_lookup *ctx)
{
	if (ctx->local_port != CONNECT_PORT)
		return BPF_OK;

	ctx->local_port = LISTEN_PORT;
	return BPF_REDIRECT;
}

/* Remap destination IP CONNECT_IP4 -> LISTEN_IP4. */
SEC("inet_lookup/remap_ip4")
int inet4_remap_ip(struct bpf_inet_lookup *ctx)
{
	if (ctx->family != AF_INET)
		return BPF_OK;
	if (ctx->local_port != CONNECT_PORT)
		return BPF_OK;
	if (ctx->local_ip4 != bpf_htonl(CONNECT_IP4))
		return BPF_OK;

	ctx->local_ip4 = bpf_htonl(LISTEN_IP4);
	return BPF_REDIRECT;
}

/* Remap destination IP CONNECT_IP6 -> LISTEN_IP6. */
SEC("inet_lookup/remap_ip6")
int inet6_remap_ip(struct bpf_inet_lookup *ctx)
{
	if (ctx->family != AF_INET6)
		return BPF_OK;
	if (ctx->local_port != CONNECT_PORT)
		return BPF_OK;
	if (ctx->local_ip6[0] != bpf_htonl(0xfd000000) ||
	    ctx->local_ip6[1] != bpf_htonl(0x00000000) ||
	    ctx->local_ip6[2] != bpf_htonl(0x00000000) ||
	    ctx->local_ip6[3] != bpf_htonl(0x00000001))
		return BPF_OK;

	ctx->local_ip6[0] = bpf_htonl(0xfd000000);
	ctx->local_ip6[1] = bpf_htonl(0x00000000);
	ctx->local_ip6[2] = bpf_htonl(0x00000000);
	ctx->local_ip6[3] = bpf_htonl(0x00000002);
	return BPF_REDIRECT;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
