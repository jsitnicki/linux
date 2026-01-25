// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cloudflare, Inc. */

#define _GNU_SOURCE
#include <test_progs.h>
#include <network_helpers.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include "cgroup_helpers.h"
#include "skb_storage_multi.skel.h"

#define CG_PATH "/skb_storage_multi"
#define MAGIC_VALUE 0xCAFEBABE
#define IFINDEX_LO 1

#define NS_SRC "skb_stg_src"
#define NS_DST "skb_stg_dst"
#define IP_SRC "10.0.0.1"
#define IP_DST "10.0.0.2"
#define PORT 4040

static int send_udp_packet(__be16 port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = port,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int fd, ret = -1;
	char buf[] = "test";

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	if (sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr,
		   sizeof(addr)) < 0)
		goto out;

	ret = 0;
out:
	close(fd);
	return ret;
}

static int recv_udp_packet(int server_fd)
{
	char buf[64];
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	return recvfrom(server_fd, buf, sizeof(buf), 0,
			(struct sockaddr *)&addr, &len);
}

static void test_udp_flow_labelling(void)
{
	struct skb_storage_multi *skel = NULL;
	struct bpf_link *tc_link = NULL;
	struct bpf_link *cg_link = NULL;
	int cgroup_fd = -1;
	int server_fd = -1;
	__be16 port;

	cgroup_fd = test__join_cgroup(CG_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = skb_storage_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	server_fd = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	skel->bss->target_port = port;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store,
					  IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tc"))
		goto cleanup;

	cg_link = bpf_program__attach_cgroup(skel->progs.cgroup_ingress_read,
					     cgroup_fd);
	if (!ASSERT_OK_PTR(cg_link, "attach_cgroup"))
		goto cleanup;

	skel->bss->tc_ingress_seen = 0;
	skel->bss->cgroup_ingress_seen = 0;
	skel->bss->cgroup_ingress_value = 0;

	if (!ASSERT_OK(send_udp_packet(port), "send_udp"))
		goto cleanup;

	if (!ASSERT_GE(recv_udp_packet(server_fd), 0, "recv_udp"))
		goto cleanup;

	ASSERT_EQ(skel->bss->tc_ingress_seen, 1, "tc_ingress_seen");
	ASSERT_EQ(skel->bss->cgroup_ingress_seen, 1, "cgroup_ingress_seen");
	ASSERT_EQ(skel->bss->cgroup_ingress_value, MAGIC_VALUE, "cgroup_ingress_value");

cleanup:
	bpf_link__destroy(cg_link);
	bpf_link__destroy(tc_link);
	if (server_fd >= 0)
		close(server_fd);
	skb_storage_multi__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void test_cross_netns(void)
{
	struct skb_storage_multi *skel = NULL;
	struct bpf_link *egress_link = NULL;
	struct bpf_link *ingress_link = NULL;
	struct nstoken *nstoken = NULL;
	int cgroup_fd = -1;
	int server_fd = -1;
	int client_fd = -1;
	__be16 port;

	SYS(cleanup, "ip netns add " NS_SRC);
	SYS(cleanup, "ip netns add " NS_DST);
	SYS(cleanup, "ip link add veth_src netns " NS_SRC " type veth peer name veth_dst netns " NS_DST);
	SYS(cleanup, "ip -n " NS_SRC " addr add " IP_SRC "/24 dev veth_src");
	SYS(cleanup, "ip -n " NS_DST " addr add " IP_DST "/24 dev veth_dst");
	SYS(cleanup, "ip -n " NS_SRC " link set veth_src up");
	SYS(cleanup, "ip -n " NS_DST " link set veth_dst up");

	cgroup_fd = test__join_cgroup(CG_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		goto cleanup;

	skel = skb_storage_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	egress_link = bpf_program__attach_cgroup(skel->progs.cgroup_egress_store,
						 cgroup_fd);
	if (!ASSERT_OK_PTR(egress_link, "attach_egress"))
		goto cleanup;

	ingress_link = bpf_program__attach_cgroup(skel->progs.cgroup_ingress_read,
						  cgroup_fd);
	if (!ASSERT_OK_PTR(ingress_link, "attach_ingress"))
		goto cleanup;

	nstoken = open_netns(NS_DST);
	if (!ASSERT_OK_PTR(nstoken, "open_netns dst"))
		goto cleanup;

	server_fd = start_server(AF_INET, SOCK_DGRAM, IP_DST, 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	close_netns(nstoken);
	nstoken = open_netns(NS_SRC);
	if (!ASSERT_OK_PTR(nstoken, "open_netns src"))
		goto cleanup;

	client_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!ASSERT_GE(client_fd, 0, "socket"))
		goto cleanup;

	skel->bss->target_port = port;
	skel->bss->cgroup_egress_seen = 0;
	skel->bss->cgroup_ingress_seen = 0;
	skel->bss->cgroup_ingress_value = 0;

	{
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = port,
		};
		char buf[] = "cross-netns-test";

		inet_pton(AF_INET, IP_DST, &addr.sin_addr);
		if (!ASSERT_GE(sendto(client_fd, buf, strlen(buf), 0,
				      (struct sockaddr *)&addr, sizeof(addr)), 0, "sendto"))
			goto cleanup;
	}

	{
		char buf[64];
		struct sockaddr_in addr;
		socklen_t len = sizeof(addr);

		if (!ASSERT_EQ(recvfrom(server_fd, buf, sizeof(buf), 0,
					(struct sockaddr *)&addr, &len),
			       strlen("cross-netns-test"), "recvfrom"))
			goto cleanup;
	}

	/* TODO: Check received message payload */

	ASSERT_EQ(skel->bss->cgroup_egress_seen, 1, "cgroup_egress_seen");
	ASSERT_EQ(skel->bss->cgroup_ingress_seen, 1, "cgroup_ingress_seen");
	ASSERT_EQ(skel->bss->cgroup_ingress_value, MAGIC_VALUE, "cross_netns_value_match");

cleanup:
	if (nstoken)
		close_netns(nstoken);
	bpf_link__destroy(ingress_link);
	bpf_link__destroy(egress_link);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	skb_storage_multi__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	SYS_NOFAIL("ip netns del " NS_SRC);
	SYS_NOFAIL("ip netns del " NS_DST);
}

static void test_tc_to_socket_filter(void)
{
	struct skb_storage_multi *skel = NULL;
	struct bpf_link *tc_link = NULL;
	int cgroup_fd = -1;
	int server_fd = -1;
	__be16 port;
	int prog_fd;

	skel = skb_storage_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	server_fd = start_server(AF_INET, SOCK_DGRAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	skel->bss->target_port = port;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store,
					  IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tc"))
		goto cleanup;

	prog_fd = bpf_program__fd(skel->progs.socket_filter_read);
	if (!ASSERT_GE(prog_fd, 0, "get_prog_fd"))
		goto cleanup;

	if (!ASSERT_OK(setsockopt(server_fd, SOL_SOCKET, SO_ATTACH_BPF,
				  &prog_fd, sizeof(prog_fd)), "attach_socket_filter"))
		goto cleanup;

	skel->bss->tc_ingress_seen = 0;
	skel->bss->socket_filter_seen = 0;
	skel->bss->socket_filter_value = 0;

	if (!ASSERT_OK(send_udp_packet(port), "send_udp"))
		goto cleanup;

	if (!ASSERT_GE(recv_udp_packet(server_fd), 0, "recv_udp"))
		goto cleanup;

	ASSERT_EQ(skel->bss->tc_ingress_seen, 1, "tc_ingress_seen");
	ASSERT_EQ(skel->bss->socket_filter_seen, 1, "socket_filter_seen");
	ASSERT_EQ(skel->bss->socket_filter_value, MAGIC_VALUE, "socket_filter_value");

cleanup:
	bpf_link__destroy(tc_link);
	if (server_fd >= 0)
		close(server_fd);
	skb_storage_multi__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

static void test_tcp_sockops(void)
{
	struct skb_storage_multi *skel = NULL;
	struct bpf_link *tc_link = NULL;
	struct bpf_link *sockops_link = NULL;
	int cgroup_fd = -1;
	int server_fd = -1;
	int client_fd = -1;
	__be16 port;

	cgroup_fd = test__join_cgroup(CG_PATH);
	if (!ASSERT_GE(cgroup_fd, 0, "join_cgroup"))
		return;

	skel = skb_storage_multi__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel_open_and_load"))
		goto cleanup;

	server_fd = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_GE(server_fd, 0, "start_server"))
		goto cleanup;

	port = get_socket_local_port(server_fd);
	if (!ASSERT_GE(port, 0, "get_port"))
		goto cleanup;

	tc_link = bpf_program__attach_tcx(skel->progs.tc_ingress_store,
					  IFINDEX_LO, NULL);
	if (!ASSERT_OK_PTR(tc_link, "attach_tc"))
		goto cleanup;

	sockops_link = bpf_program__attach_cgroup(skel->progs.sockops_read,
						  cgroup_fd);
	if (!ASSERT_OK_PTR(sockops_link, "attach_sockops"))
		goto cleanup;

	skel->bss->target_port = port;
	skel->bss->tc_ingress_seen = 0;
	skel->bss->sock_ops_seen = 0;
	skel->bss->sock_ops_value = 0;

	client_fd = connect_to_fd(server_fd, 0);
	if (!ASSERT_GE(client_fd, 0, "connect"))
		goto cleanup;

	{
		int accepted_fd = accept(server_fd, NULL, NULL);
		if (!ASSERT_GE(accepted_fd, 0, "accept"))
			goto cleanup;
		close(accepted_fd);
	}

	ASSERT_GT(skel->bss->tc_ingress_seen, 0, "tc_ingress_seen");
	ASSERT_GT(skel->bss->sock_ops_seen, 0, "sock_ops_seen");
	ASSERT_EQ(skel->bss->sock_ops_value, MAGIC_VALUE, "sock_ops_value");

cleanup:
	bpf_link__destroy(sockops_link);
	bpf_link__destroy(tc_link);
	if (client_fd >= 0)
		close(client_fd);
	if (server_fd >= 0)
		close(server_fd);
	skb_storage_multi__destroy(skel);
	if (cgroup_fd >= 0)
		close(cgroup_fd);
}

void test_skb_storage_multi(void)
{
	if (test__start_subtest("udp_flow_labelling"))
		test_udp_flow_labelling();
	if (test__start_subtest("cross_netns"))
		test_cross_netns();
	if (test__start_subtest("tc_to_socket_filter"))
		test_tc_to_socket_filter();
	if (test__start_subtest("tcp_sockops"))
		test_tcp_sockops();
}
