// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2023 Cloudflare

/* Test IP_LOCAL_PORT_RANGE socket option: IPv4 + IPv6, TCP + UDP.
 *
 * Tests assume that net.ipv4.ip_local_port_range is [40000, 49999].
 * Don't run these directly but with ip_local_port_range.sh script.
 */

#include <fcntl.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "../kselftest_harness.h"

#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

static const int ONE = 1;

__attribute__((nonnull)) static inline void close_fd(int *fd)
{
	close(*fd);
}

#define __close_fd __attribute__((cleanup(close_fd)))

static __u32 pack_port_range(__u16 lo, __u16 hi)
{
	return (hi << 16) | (lo << 0);
}

static void unpack_port_range(__u32 range, __u16 *lo, __u16 *hi)
{
	*lo = range & 0xffff;
	*hi = range >> 16;
}

static int get_so_domain(int fd)
{
	int domain, err;
	socklen_t len;

	len = sizeof(domain);
	err = getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len);
	if (err)
		return -1;

	return domain;
}

static int bind_to_loopback_any_port(int fd)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr;
	socklen_t addr_len;

	memset(&addr, 0, sizeof(addr));
	switch (get_so_domain(fd)) {
	case AF_INET:
		addr.v4.sin_family = AF_INET;
		addr.v4.sin_port = htons(0);
		addr.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_len = sizeof(addr.v4);
		break;
	case AF_INET6:
		addr.v6.sin6_family = AF_INET6;
		addr.v6.sin6_port = htons(0);
		addr.v6.sin6_addr = in6addr_loopback;
		addr_len = sizeof(addr.v6);
		break;
	default:
		return -1;
	}

	return bind(fd, &addr.sa, addr_len);
}

static int get_sock_port(int fd)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr;
	socklen_t addr_len;
	int err;

	addr_len = sizeof(addr);
	memset(&addr, 0, sizeof(addr));
	err = getsockname(fd, &addr.sa, &addr_len);
	if (err)
		return -1;

	switch (addr.sa.sa_family) {
	case AF_INET:
		return ntohs(addr.v4.sin_port);
	case AF_INET6:
		return ntohs(addr.v6.sin6_port);
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}
}

static int get_ip_local_port_range(int fd, __u32 *range)
{
	socklen_t len;
	__u32 val;
	int err;

	len = sizeof(val);
	err = getsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &val, &len);
	if (err)
		return -1;

	*range = val;
	return 0;
}

struct sockaddr_inet {
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 v6;
		struct sockaddr_in v4;
		struct sockaddr sa;
	};
	socklen_t len;
};

static void make_inet_addr(int af, const char *ip, __u16 port,
			   struct sockaddr_inet *addr)
{
	memset(addr, 0, sizeof(*addr));

	switch (af) {
	case AF_INET:
		addr->len = sizeof(addr->v4);
		addr->v4.sin_family = af;
		addr->v4.sin_port = htons(port);
		inet_pton(af, ip, &addr->v4.sin_addr);
		break;
	case AF_INET6:
		addr->len = sizeof(addr->v6);
		addr->v6.sin6_family = af;
		addr->v6.sin6_port = htons(port);
		inet_pton(af, ip, &addr->v6.sin6_addr);
		break;
	}
}

static bool is_v4mapped(const struct sockaddr_inet *a)
{
	return (a->sa.sa_family == AF_INET6 &&
		IN6_IS_ADDR_V4MAPPED(&a->v6.sin6_addr));
}

static void v4mapped_to_ipv4(struct sockaddr_inet *a)
{
	in_port_t port = a->v6.sin6_port;
	in_addr_t ip4 = *(in_addr_t *)&a->v6.sin6_addr.s6_addr[12];

	memset(a, 0, sizeof(*a));
	a->len = sizeof(a->v4);
	a->v4.sin_family = AF_INET;
	a->v4.sin_port = port;
	a->v4.sin_addr.s_addr = ip4;
}

static void ipv4_to_v4mapped(struct sockaddr_inet *a)
{
	in_port_t port = a->v4.sin_port;
	in_addr_t ip4 = a->v4.sin_addr.s_addr;

	memset(a, 0, sizeof(*a));
	a->len = sizeof(a->v6);
	a->v6.sin6_family = AF_INET6;
	a->v6.sin6_port = port;
	a->v6.sin6_addr.s6_addr[10] = 0xff;
	a->v6.sin6_addr.s6_addr[11] = 0xff;
	memcpy(&a->v6.sin6_addr.s6_addr[12], &ip4, sizeof(ip4));
}

static __u16 inet_port(const struct sockaddr_inet *a)
{
	switch (a->sa.sa_family) {
	case AF_INET:
		return ntohs(a->v4.sin_port);
	case AF_INET6:
		return ntohs(a->v6.sin6_port);
	default:
		return 0;
	}
}

FIXTURE(ip_local_port_range) {};

FIXTURE_SETUP(ip_local_port_range)
{
}

FIXTURE_TEARDOWN(ip_local_port_range)
{
}

FIXTURE_VARIANT(ip_local_port_range) {
	int so_domain;
	int so_type;
	int so_protocol;
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip4_tcp) {
	.so_domain	= AF_INET,
	.so_type	= SOCK_STREAM,
	.so_protocol	= 0,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip4_udp) {
	.so_domain	= AF_INET,
	.so_type	= SOCK_DGRAM,
	.so_protocol	= 0,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip4_stcp) {
	.so_domain	= AF_INET,
	.so_type	= SOCK_STREAM,
	.so_protocol	= IPPROTO_SCTP,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip4_mptcp) {
	.so_domain	= AF_INET,
	.so_type	= SOCK_STREAM,
	.so_protocol	= IPPROTO_MPTCP,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip6_tcp) {
	.so_domain	= AF_INET6,
	.so_type	= SOCK_STREAM,
	.so_protocol	= 0,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip6_udp) {
	.so_domain	= AF_INET6,
	.so_type	= SOCK_DGRAM,
	.so_protocol	= 0,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip6_stcp) {
	.so_domain	= AF_INET6,
	.so_type	= SOCK_STREAM,
	.so_protocol	= IPPROTO_SCTP,
};

FIXTURE_VARIANT_ADD(ip_local_port_range, ip6_mptcp) {
	.so_domain	= AF_INET6,
	.so_type	= SOCK_STREAM,
	.so_protocol	= IPPROTO_MPTCP,
};

TEST_F(ip_local_port_range, invalid_option_value)
{
	__u16 val16;
	__u32 val32;
	__u64 val64;
	int fd, err;

	fd = socket(variant->so_domain, variant->so_type, variant->so_protocol);
	ASSERT_GE(fd, 0) TH_LOG("socket failed");

	/* Too few bytes */
	val16 = 40000;
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &val16, sizeof(val16));
	EXPECT_TRUE(err) TH_LOG("expected setsockopt(IP_LOCAL_PORT_RANGE) to fail");
	EXPECT_EQ(errno, EINVAL);

	/* Empty range: low port > high port */
	val32 = pack_port_range(40222, 40111);
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &val32, sizeof(val32));
	EXPECT_TRUE(err) TH_LOG("expected setsockopt(IP_LOCAL_PORT_RANGE) to fail");
	EXPECT_EQ(errno, EINVAL);

	/* Too many bytes */
	val64 = pack_port_range(40333, 40444);
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &val64, sizeof(val64));
	EXPECT_TRUE(err) TH_LOG("expected setsockopt(IP_LOCAL_PORT_RANGE) to fail");
	EXPECT_EQ(errno, EINVAL);

	err = close(fd);
	ASSERT_TRUE(!err) TH_LOG("close failed");
}

TEST_F(ip_local_port_range, port_range_out_of_netns_range)
{
	const struct test {
		__u16 range_lo;
		__u16 range_hi;
	} tests[] = {
		{ 30000, 39999 }, /* socket range below netns range */
		{ 50000, 59999 }, /* socket range above netns range */
	};
	const struct test *t;

	for (t = tests; t < tests + ARRAY_SIZE(tests); t++) {
		/* Bind a couple of sockets, not just one, to check
		 * that the range wasn't clamped to a single port from
		 * the netns range. That is [40000, 40000] or [49999,
		 * 49999], respectively for each test case.
		 */
		int fds[2], i;

		TH_LOG("lo %5hu, hi %5hu", t->range_lo, t->range_hi);

		for (i = 0; i < ARRAY_SIZE(fds); i++) {
			int fd, err, port;
			__u32 range;

			fd = socket(variant->so_domain, variant->so_type, variant->so_protocol);
			ASSERT_GE(fd, 0) TH_LOG("#%d: socket failed", i);

			range = pack_port_range(t->range_lo, t->range_hi);
			err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
			ASSERT_TRUE(!err) TH_LOG("#%d: setsockopt(IP_LOCAL_PORT_RANGE) failed", i);

			err = bind_to_loopback_any_port(fd);
			ASSERT_TRUE(!err) TH_LOG("#%d: bind failed", i);

			/* Check that socket port range outside of ephemeral range is ignored */
			port = get_sock_port(fd);
			ASSERT_GE(port, 40000) TH_LOG("#%d: expected port within netns range", i);
			ASSERT_LE(port, 49999) TH_LOG("#%d: expected port within netns range", i);

			fds[i] = fd;
		}

		for (i = 0; i < ARRAY_SIZE(fds); i++)
			ASSERT_TRUE(close(fds[i]) == 0) TH_LOG("#%d: close failed", i);
	}
}

TEST_F(ip_local_port_range, single_port_range)
{
	const struct test {
		__u16 range_lo;
		__u16 range_hi;
		__u16 expected;
	} tests[] = {
		/* single port range within ephemeral range */
		{ 45000, 45000, 45000 },
		/* first port in the ephemeral range (clamp from above) */
		{ 0, 40000, 40000 },
		/* last port in the ephemeral range (clamp from below)  */
		{ 49999, 0, 49999 },
	};
	const struct test *t;

	for (t = tests; t < tests + ARRAY_SIZE(tests); t++) {
		int fd, err, port;
		__u32 range;

		TH_LOG("lo %5hu, hi %5hu, expected %5hu",
		       t->range_lo, t->range_hi, t->expected);

		fd = socket(variant->so_domain, variant->so_type, variant->so_protocol);
		ASSERT_GE(fd, 0) TH_LOG("socket failed");

		range = pack_port_range(t->range_lo, t->range_hi);
		err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
		ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE) failed");

		err = bind_to_loopback_any_port(fd);
		ASSERT_TRUE(!err) TH_LOG("bind failed");

		port = get_sock_port(fd);
		ASSERT_EQ(port, t->expected) TH_LOG("unexpected local port");

		err = close(fd);
		ASSERT_TRUE(!err) TH_LOG("close failed");
	}
}

TEST_F(ip_local_port_range, exhaust_8_port_range)
{
	__u8 port_set = 0;
	int i, fd, err;
	__u32 range;
	__u16 port;
	int fds[8];

	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		fd = socket(variant->so_domain, variant->so_type, variant->so_protocol);
		ASSERT_GE(fd, 0) TH_LOG("socket failed");

		range = pack_port_range(40000, 40007);
		err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
		ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE) failed");

		err = bind_to_loopback_any_port(fd);
		ASSERT_TRUE(!err) TH_LOG("bind failed");

		port = get_sock_port(fd);
		ASSERT_GE(port, 40000) TH_LOG("expected port within sockopt range");
		ASSERT_LE(port, 40007) TH_LOG("expected port within sockopt range");

		port_set |= 1 << (port - 40000);
		fds[i] = fd;
	}

	/* Check that all every port from the test range is in use */
	ASSERT_EQ(port_set, 0xff) TH_LOG("expected all ports to be busy");

	/* Check that bind() fails because the whole range is busy */
	fd = socket(variant->so_domain, variant->so_type, variant->so_protocol);
	ASSERT_GE(fd, 0) TH_LOG("socket failed");

	range = pack_port_range(40000, 40007);
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE) failed");

	err = bind_to_loopback_any_port(fd);
	ASSERT_TRUE(err) TH_LOG("expected bind to fail");
	ASSERT_EQ(errno, EADDRINUSE);

	err = close(fd);
	ASSERT_TRUE(!err) TH_LOG("close failed");

	for (i = 0; i < ARRAY_SIZE(fds); i++) {
		err = close(fds[i]);
		ASSERT_TRUE(!err) TH_LOG("close failed");
	}
}

TEST_F(ip_local_port_range, late_bind)
{
	union {
		struct sockaddr sa;
		struct sockaddr_in v4;
		struct sockaddr_in6 v6;
	} addr;
	socklen_t addr_len = 0;
	const int one = 1;
	int fd, err;
	__u32 range;
	__u16 port;

	fd = socket(variant->so_domain, variant->so_type, 0);
	ASSERT_GE(fd, 0) TH_LOG("socket failed");

	range = pack_port_range(40100, 40199);
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE) failed");

	err = setsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &one, sizeof(one));
	ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_BIND_ADDRESS_NO_PORT) failed");

	err = bind_to_loopback_any_port(fd);
	ASSERT_TRUE(!err) TH_LOG("bind failed");

	port = get_sock_port(fd);
	ASSERT_EQ(port, 0) TH_LOG("getsockname failed");

	/* Invalid destination */
	memset(&addr, 0, sizeof(addr));
	switch (variant->so_domain) {
	case AF_INET:
		addr.v4.sin_family = AF_INET;
		addr.v4.sin_port = htons(0);
		addr.v4.sin_addr.s_addr = htonl(INADDR_ANY);
		addr_len = sizeof(addr.v4);
		break;
	case AF_INET6:
		addr.v6.sin6_family = AF_INET6;
		addr.v6.sin6_port = htons(0);
		addr.v6.sin6_addr = in6addr_any;
		addr_len = sizeof(addr.v6);
		break;
	default:
		ASSERT_TRUE(false) TH_LOG("unsupported socket domain");
	}

	/* connect() doesn't need to succeed for late bind to happen */
	connect(fd, &addr.sa, addr_len);

	port = get_sock_port(fd);
	ASSERT_GE(port, 40100);
	ASSERT_LE(port, 40199);

	err = close(fd);
	ASSERT_TRUE(!err) TH_LOG("close failed");
}

XFAIL_ADD(ip_local_port_range, ip4_stcp, late_bind);
XFAIL_ADD(ip_local_port_range, ip6_stcp, late_bind);

TEST_F(ip_local_port_range, get_port_range)
{
	__u16 lo, hi;
	__u32 range;
	int fd, err;

	fd = socket(variant->so_domain, variant->so_type, variant->so_protocol);
	ASSERT_GE(fd, 0) TH_LOG("socket failed");

	/* Get range before it will be set */
	err = get_ip_local_port_range(fd, &range);
	ASSERT_TRUE(!err) TH_LOG("getsockopt(IP_LOCAL_PORT_RANGE) failed");

	unpack_port_range(range, &lo, &hi);
	ASSERT_EQ(lo, 0) TH_LOG("unexpected low port");
	ASSERT_EQ(hi, 0) TH_LOG("unexpected high port");

	range = pack_port_range(12345, 54321);
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE) failed");

	/* Get range after it has been set */
	err = get_ip_local_port_range(fd, &range);
	ASSERT_TRUE(!err) TH_LOG("getsockopt(IP_LOCAL_PORT_RANGE) failed");

	unpack_port_range(range, &lo, &hi);
	ASSERT_EQ(lo, 12345) TH_LOG("unexpected low port");
	ASSERT_EQ(hi, 54321) TH_LOG("unexpected high port");

	/* Unset the port range  */
	range = pack_port_range(0, 0);
	err = setsockopt(fd, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_TRUE(!err) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE) failed");

	/* Get range after it has been unset */
	err = get_ip_local_port_range(fd, &range);
	ASSERT_TRUE(!err) TH_LOG("getsockopt(IP_LOCAL_PORT_RANGE) failed");

	unpack_port_range(range, &lo, &hi);
	ASSERT_EQ(lo, 0) TH_LOG("unexpected low port");
	ASSERT_EQ(hi, 0) TH_LOG("unexpected high port");

	err = close(fd);
	ASSERT_TRUE(!err) TH_LOG("close failed");
}

FIXTURE(tcp_port_reuse__no_ip_conflict) {};
FIXTURE_SETUP(tcp_port_reuse__no_ip_conflict) {}
FIXTURE_TEARDOWN(tcp_port_reuse__no_ip_conflict) {}

FIXTURE_VARIANT(tcp_port_reuse__no_ip_conflict) {
	int af_one;
	const char *ip_one;
	int af_two;
	const char *ip_two;
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__no_ip_conflict, ipv4) {
	.af_one = AF_INET,
	.ip_one = "127.0.0.1",
	.af_two = AF_INET,
	.ip_two = "127.0.0.2",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__no_ip_conflict, ipv6_v4mapped) {
	.af_one = AF_INET6,
	.ip_one = "::ffff:127.0.0.1",
	.af_two = AF_INET,
	.ip_two = "127.0.0.2",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__no_ip_conflict, ipv6) {
	.af_one = AF_INET6,
	.ip_one = "2001:db8::1",
	.af_two = AF_INET6,
	.ip_two = "2001:db8::2",
};

/* Check that a connected socket, which is using IP_LOCAL_PORT_RANGE to relax
 * port search restrictions at connect() time, can share a local port with a
 * listening socket bound to a different IP.
 */
TEST_F(tcp_port_reuse__no_ip_conflict, share_port_with_listening_socket)
{
	const typeof(variant) v = variant;
	struct sockaddr_inet addr;
	__close_fd int ln = -1;
	__close_fd int c = -1;
	__close_fd int p = -1;
	__u32 range;
	int r;

	/* Listen on <ip one>:40000 */
	ln = socket(v->af_one, SOCK_STREAM, 0);
	ASSERT_GE(ln, 0) TH_LOG("socket");

	r = setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(SO_REUSEADDR)");

	make_inet_addr(v->af_one, v->ip_one, 40000, &addr);
	r = bind(ln, &addr.sa, addr.len);
	ASSERT_EQ(r, 0) TH_LOG("bind(<ip_one>:40000)");

	r = listen(ln, 1);
	ASSERT_EQ(r, 0) TH_LOG("listen");

	/* Connect from <ip two>:40000 to <ip one>:40000 */
	c = socket(v->af_two, SOCK_STREAM, 0);
	ASSERT_GE(c, 0) TH_LOG("socket");

	r = setsockopt(c, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &ONE, sizeof(ONE));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(IP_BIND_ADDRESS_NO_PORT)");

	range = pack_port_range(40000, 40000);
	r = setsockopt(c, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE)");

	make_inet_addr(v->af_two, v->ip_two, 0, &addr);
	r = bind(c, &addr.sa, addr.len);
	ASSERT_EQ(r, 0) TH_LOG("bind(<ip_two>:0)");

	make_inet_addr(v->af_one, v->ip_one, 40000, &addr);
	if (is_v4mapped(&addr))
		v4mapped_to_ipv4(&addr);
	r = connect(c, &addr.sa, addr.len);
	EXPECT_EQ(r, 0) TH_LOG("connect(<ip_one>:40000)");
	EXPECT_EQ(get_sock_port(c), 40000);
}

/* Check that a connected socket, which is using IP_LOCAL_PORT_RANGE to relax
 * port search restrictions at connect() time, can share a local port with
 * another connected socket bound to a different IP without
 * IP_BIND_ADDRESS_NO_PORT enabled.
 */
TEST_F(tcp_port_reuse__no_ip_conflict, share_port_with_connected_socket)
{
	const typeof(variant) v = variant;
	struct sockaddr_inet dst = {};
	struct sockaddr_inet src = {};
	__close_fd int ln = -1;
	__close_fd int c1 = -1;
	__close_fd int c2 = -1;
	__u32 range;
	__u16 port;
	int r;

	/* Listen on wildcard. Same family as <ip_two>. */
	ln = socket(v->af_two, SOCK_STREAM, 0);
	ASSERT_GE(ln, 0) TH_LOG("socket");

	r = setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(SO_REUSEADDR");

	r = listen(ln, 2);
	ASSERT_EQ(r, 0) TH_LOG("listen");

	dst.len = sizeof(dst.ss);
	r = getsockname(ln, &dst.sa, &dst.len);
	ASSERT_EQ(r, 0) TH_LOG("getsockname");

	/* Connect from <ip one> but without IP_BIND_ADDRESS_NO_PORT */
	c1 = socket(v->af_one, SOCK_STREAM, 0);
	ASSERT_GE(c1, 0) TH_LOG("socket");

	make_inet_addr(v->af_one, v->ip_one, 0, &src);
	r = bind(c1, &src.sa, src.len);
	ASSERT_EQ(r, 0) TH_LOG("bind");

	if (src.sa.sa_family == AF_INET6 && dst.sa.sa_family == AF_INET)
		ipv4_to_v4mapped(&dst);
	r = connect(c1, &dst.sa, dst.len);
	ASSERT_EQ(r, 0) TH_LOG("connect");

	src.len = sizeof(src.ss);
	r = getsockname(c1, &src.sa, &src.len);
	ASSERT_EQ(r, 0) TH_LOG("getsockname");

	/* Connect from <ip two>:<c1 port> with IP_BIND_ADDRESS_NO_PORT */
	c2 = socket(v->af_two, SOCK_STREAM, 0);
	ASSERT_GE(c2, 0) TH_LOG("socket");

	r = setsockopt(c2, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &ONE, sizeof(ONE));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(IP_BIND_ADDRESS_NO_PORT)");

	port = inet_port(&src);
	range = pack_port_range(port, port);
	r = setsockopt(c2, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE)");

	make_inet_addr(v->af_two, v->ip_two, 0, &src);
	r = bind(c2, &src.sa, src.len);
	ASSERT_EQ(r, 0) TH_LOG("bind");

	if (is_v4mapped(&dst))
		v4mapped_to_ipv4(&dst);
	r = connect(c2, &dst.sa, dst.len);
	EXPECT_EQ(r, 0) TH_LOG("connect");
	EXPECT_EQ(get_sock_port(c2), port);
}

FIXTURE(tcp_port_reuse__ip_conflict) {};
FIXTURE_SETUP(tcp_port_reuse__ip_conflict) {}
FIXTURE_TEARDOWN(tcp_port_reuse__ip_conflict) {}

FIXTURE_VARIANT(tcp_port_reuse__ip_conflict) {
	int af_one;
	const char *ip_one;
	int af_two;
	const char *ip_two;
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__ip_conflict, ipv4) {
	.af_one = AF_INET,
	.ip_one = "127.0.0.1",
	.af_two = AF_INET,
	.ip_two = "127.0.0.1",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__ip_conflict, ipv6_v4mapped) {
	.af_one = AF_INET6,
	.ip_one = "::ffff:127.0.0.1",
	.af_two = AF_INET,
	.ip_two = "127.0.0.1",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__ip_conflict, ipv6) {
	.af_one = AF_INET6,
	.ip_one = "2001:db8::1",
	.af_two = AF_INET6,
	.ip_two = "2001:db8::1",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__ip_conflict, ipv4_wildcard) {
	.af_one = AF_INET,
	.ip_one = "0.0.0.0",
	.af_two = AF_INET,
	.ip_two = "127.0.0.1",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__ip_conflict, ipv6_v4mapped_wildcard) {
	.af_one = AF_INET6,
	.ip_one = "::ffff:0.0.0.0",
	.af_two = AF_INET,
	.ip_two = "127.0.0.1",
};

FIXTURE_VARIANT_ADD(tcp_port_reuse__ip_conflict, ipv6_wildcard) {
	.af_one = AF_INET6,
	.ip_one = "::",
	.af_two = AF_INET6,
	.ip_two = "2001:db8::1",
};

/* Check that a socket, which using IP_LOCAL_PORT_RANGE to relax local port
 * search restrictions at connect() time, can't share a local port with a
 * listening socket when there is IP address conflict.
 */
TEST_F(tcp_port_reuse__ip_conflict, cannot_share_port)
{
	const typeof(variant) v = variant;
	struct sockaddr_inet dst, src;
	__close_fd int ln = -1;
	__close_fd int c = -1;
	__u32 range;
	int r;

	/* Listen on <ip_one>:40000 */
	ln = socket(v->af_one, SOCK_STREAM, 0);
	ASSERT_GE(ln, 0) TH_LOG("socket");

	r = setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(ONE));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(SO_REUSEADDR)");

	make_inet_addr(v->af_one, v->ip_one, 40000, &dst);
	r = bind(ln, &dst.sa, dst.len);
	ASSERT_EQ(r, 0) TH_LOG("bind(<ip_one>:40000)");

	r = listen(ln, 1);
	ASSERT_EQ(r, 0) TH_LOG("listen");

	/* Attempt to connect from <ip two>:40000 */
	c = socket(v->af_two, SOCK_STREAM, 0);
	ASSERT_GE(c, 0) TH_LOG("socket");

	r = setsockopt(c, SOL_IP, IP_BIND_ADDRESS_NO_PORT, &ONE, sizeof(ONE));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(IP_BIND_ADDRESS_NO_PORT)");

	range = pack_port_range(40000, 40000);
	r = setsockopt(c, SOL_IP, IP_LOCAL_PORT_RANGE, &range, sizeof(range));
	ASSERT_EQ(r, 0) TH_LOG("setsockopt(IP_LOCAL_PORT_RANGE)");

	make_inet_addr(v->af_two, v->ip_two, 0, &src);
	r = bind(c, &src.sa, src.len);
	ASSERT_EQ(r, 0) TH_LOG("bind(<ip_two>:40000)");

	if (is_v4mapped(&dst))
		v4mapped_to_ipv4(&dst);
	r = connect(c, &dst.sa, dst.len);
	EXPECT_EQ(r, -1) TH_LOG("connect(*:40000)");
	EXPECT_EQ(errno, EADDRNOTAVAIL);
}

TEST_HARNESS_MAIN
