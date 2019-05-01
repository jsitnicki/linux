// SPDX-License-Identifier: GPL-2.0
/*
 * L7 echo tests with the server listening on a different (address,
 * port) than the client sends packets to.
 *
 * Traffic is steered to the server socket by programming the socket
 * lookup with a BPF inet_lookup program. The inet_lookup program
 * selects the listening socket from a user-space supplied SOCKMAP
 * based on the packet's 4-tuple.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "bpf_rlimit.h"
#include "bpf_util.h"

#define BPF_FILE	"./inet_lookup_progs.o"
#define MAX_ERROR_LEN	256

/* External (address, port) pairs the client sends packets to. */
#define EXT_IP4		"127.0.0.1"
#define EXT_IP6		"fd00::1"
#define EXT_PORT	7007

/* Internal (address, port) pairs the server listens/receives at. */
#define INT_IP4		"127.0.0.2"
#define INT_IP4_V6	"::ffff:127.0.0.2"
#define INT_IP6		"fd00::2"
#define INT_PORT	8008

struct inet_addr {
	const char *ip;
	unsigned short port;
};

struct test {
	const char *desc;
	const char *bpf_prog;

	int socket_type;

	struct inet_addr send_to;
	struct inet_addr recv_at;
};

static const struct test tests[] = {
	{
		.desc		= "TCP IPv4 redir port",
		.bpf_prog	= "inet_lookup/redir_port",
		.socket_type	= SOCK_STREAM,
		.send_to	= { EXT_IP4, EXT_PORT },
		.recv_at	= { EXT_IP4, INT_PORT },
	},
	{
		.desc		= "TCP IPv4 redir addr",
		.bpf_prog	= "inet_lookup/redir_ip4",
		.socket_type	= SOCK_STREAM,
		.send_to	= { EXT_IP4, EXT_PORT },
		.recv_at	= { INT_IP4, EXT_PORT },
	},
	{
		.desc		= "TCP IPv6 redir port",
		.bpf_prog	= "inet_lookup/redir_port",
		.socket_type	= SOCK_STREAM,
		.send_to	= { EXT_IP6, EXT_PORT },
		.recv_at	= { EXT_IP6, INT_PORT },
	},
	{
		.desc		= "TCP IPv6 redir addr",
		.bpf_prog	= "inet_lookup/redir_ip6",
		.socket_type	= SOCK_STREAM,
		.send_to	= { EXT_IP6, EXT_PORT },
		.recv_at	= { INT_IP6, EXT_PORT },
	},
	{
		.desc		= "TCP IPv4->IPv6 redir port",
		.bpf_prog	= "inet_lookup/redir_port",
		.socket_type	= SOCK_STREAM,
		.recv_at	= { INT_IP4_V6, INT_PORT },
		.send_to	= { EXT_IP4, EXT_PORT },
	},
};

static bool is_ipv6_addr(const char *ip)
{
	return !!strchr(ip, ':');
}

static void make_addr(int family, const char *ip, int port,
		      struct sockaddr_storage *ss, int *sz)
{
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;

	switch (family) {
	case AF_INET:
		addr4 = (struct sockaddr_in *)ss;
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(port);
		if (!inet_pton(AF_INET, ip, &addr4->sin_addr))
			error(1, errno, "inet_pton failed: %s", ip);
		*sz = sizeof(*addr4);
		break;
	case AF_INET6:
		addr6 = (struct sockaddr_in6 *)ss;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(port);
		if (!inet_pton(AF_INET6, ip, &addr6->sin6_addr))
			error(1, errno, "inet_pton failed: %s", ip);
		*sz = sizeof(*addr6);
		break;
	default:
		error(1, 0, "unsupported family %d", family);
	}
}

static int make_server(int type, const char *ip, int port)
{
	struct sockaddr_storage ss = {0};
	int fd, sz;
	int family;

	family = is_ipv6_addr(ip) ? AF_INET6 : AF_INET;
	make_addr(family, ip, port, &ss, &sz);

	fd = socket(family, type, 0);
	if (fd < 0)
		error(1, errno, "failed to create listen socket");

	if (bind(fd, (struct sockaddr *)&ss, sz))
		error(1, errno, "failed to bind listen socket");

	if (type == SOCK_STREAM && listen(fd, 1))
		error(1, errno, "failed to listen on port %d", port);

	return fd;
}

static int make_client(int type, const char *ip, int port)
{
	struct sockaddr_storage ss = {0};
	struct sockaddr *sa;
	int family;
	int fd, sz;

	family = is_ipv6_addr(ip) ? AF_INET6 : AF_INET;
	make_addr(family, ip, port, &ss, &sz);
	sa = (struct sockaddr *)&ss;

	fd = socket(family, type, 0);
	if (fd < 0)
		error(1, errno, "failed to create socket");

	if (connect(fd, sa, sz))
		error(1, errno, "failed to connect socket");

	return fd;
}

static void send_byte(int fd)
{
	if (send(fd, "a", 1, 0) < 1)
		error(1, errno, "failed to send message");
}

static void recv_byte(int fd)
{
	char buf[1];

	if (recv(fd, buf, sizeof(buf), 0) < 1)
		error(1, errno, "failed to receive message");
}

static void tcp_recv_send(int server_fd)
{
	char buf[1];
	size_t len;
	ssize_t n;
	int fd;

	fd = accept(server_fd, NULL, NULL);
	if (fd < 0)
		error(1, errno, "failed to accept");

	len = sizeof(buf);
	n = recv(fd, buf, len, 0);
	if (n < 0)
		error(1, errno, "failed to receive");
	if (n < len)
		error(1, 0, "partial receive");

	n = send(fd, buf, len, 0);
	if (n < 0)
		error(1, errno, "failed to send");
	if (n < len)
		error(1, 0, "partial send");

	close(fd);
}

static void tcp_echo(int client_fd, int server_fd)
{
	send_byte(client_fd);
	tcp_recv_send(server_fd);
	recv_byte(client_fd);
}

static struct bpf_object *load_prog(void)
{
	char buf[MAX_ERROR_LEN];
	struct bpf_object *obj;
	int prog_fd;
	int err;

	err = bpf_prog_load(BPF_FILE, BPF_PROG_TYPE_UNSPEC, &obj, &prog_fd);
	if (err) {
		libbpf_strerror(err, buf, ARRAY_SIZE(buf));
		error(1, 0, "failed to open bpf file '%s': %s", BPF_FILE, buf);
	}

	return obj;
}

static void attach_prog(struct bpf_object *obj, const char *sec)
{
	enum bpf_attach_type attach_type;
	struct bpf_program *prog;
	char buf[MAX_ERROR_LEN];
	int target_fd = -1;
	int prog_fd;
	int err;

	prog = bpf_object__find_program_by_title(obj, sec);
	err = libbpf_get_error(prog);
	if (err) {
		libbpf_strerror(err, buf, ARRAY_SIZE(buf));
		error(1, 0, "failed to find section \"%s\": %s", sec, buf);
	}

	err = libbpf_attach_type_by_name(sec, &attach_type);
	if (err) {
		libbpf_strerror(err, buf, ARRAY_SIZE(buf));
		error(1, 0, "failed to identify attach type: %s", buf);
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0)
		error(1, errno, "failed to get prog fd");

	err = bpf_prog_attach(prog_fd, target_fd, attach_type, 0);
	if (err)
		error(1, -err, "failed to attach prog");
}

static void detach_prog(const char *sec)
{
	enum bpf_attach_type attach_type;
	char buf[MAX_ERROR_LEN];
	int target_fd = -1;
	int err;

	err = libbpf_attach_type_by_name(sec, &attach_type);
	if (err) {
		libbpf_strerror(err, buf, ARRAY_SIZE(buf));
		error(1, 0, "failed to identify attach type: %s", buf);
	}

	err = bpf_prog_detach(target_fd, attach_type);
	if (err && err != -EPERM)
		error(1, -err, "failed to detach prog");
}

static void update_redir_map(int map_fd, int index, int sock_fd)
{
	uint64_t value;
	int err;

	value = (uint64_t)sock_fd;
	err = bpf_map_update_elem(map_fd, &index, &value, BPF_NOEXIST);
	if (err)
		error(1, errno, "failed to update redir_map @ %d", index);
}

static void test_prog_query(void)
{
	__u32 attach_flags = 0;
	__u32 prog_ids[1] = { 0 };
	__u32 prog_cnt = 1;
	int fd, err;

	fd = open("/proc/self/ns/net", O_RDONLY);
	if (fd < 0)
		error(1, errno, "failed to open /proc/self/ns/net");

	err = bpf_prog_query(fd, BPF_INET_LOOKUP, 0,
			     &attach_flags, prog_ids, &prog_cnt);
	if (err)
		error(1, errno, "failed to query BPF_INET_LOOKUP prog");

	assert(attach_flags == 0);
	assert(prog_cnt == 1);
	assert(prog_ids[0] != 0);

	close(fd);
}

static void run_test(const struct test *t, struct bpf_object *obj,
		     int redir_map)
{
	int client_fd, server_fd;

	fprintf(stderr, "test %s... ", t->desc);

	/* Clean up after any previous failed test runs */
	detach_prog(t->bpf_prog);

	attach_prog(obj, t->bpf_prog);
	test_prog_query();

	server_fd = make_server(t->socket_type,
				t->recv_at.ip, t->recv_at.port);
	update_redir_map(redir_map, 0, server_fd);

	client_fd = make_client(t->socket_type,
				t->send_to.ip, t->send_to.port);

	tcp_echo(client_fd, server_fd);

	close(client_fd);
	close(server_fd);

	detach_prog(t->bpf_prog);
	fprintf(stderr, "OK\n");
}

static int find_redir_map(struct bpf_object *obj)
{
	struct bpf_map *map;
	int fd;

	map = bpf_object__find_map_by_name(obj, "redir_map");
	if (!map)
		error(1, 0, "failed to find 'redir_map'");
	fd = bpf_map__fd(map);
	if (fd < 0)
		error(1, 0, "failed to get 'redir_map' fd");

	return fd;
}

int main(void)
{
	struct bpf_object *obj;
	const struct test *t;
	int redir_map;

	obj = load_prog();
	redir_map = find_redir_map(obj);

	for (t = tests; t < tests + ARRAY_SIZE(tests); t++)
		run_test(t, obj, redir_map);

	close(redir_map);
	bpf_object__unload(obj);

	fprintf(stderr, "PASS\n");
	return 0;
}
