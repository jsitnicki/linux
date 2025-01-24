// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

extern int bpf_xdp_trait_set(const struct xdp_md *xdp, __u64 key,
			     const void *val, __u64 val__sz,
			     __u64 flags) __ksym;

SEC("license") const char __license[] = "GPL";

SEC("xdp") int pass(struct xdp_md *ctx)
{
	__u16 val = 3456;
	int err = bpf_xdp_trait_set(ctx, 12, &val, sizeof(val), 0);
	if (err < 0) {
		bpf_printk("XDP: err setting trait 12: %d", err);
		return XDP_PASS;
	}
	
	bpf_printk("XDP: trait 12 set to %d", val);
	return XDP_PASS;
}
