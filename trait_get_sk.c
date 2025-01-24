// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

extern int bpf_skb_trait_get(const struct __sk_buff *skb, __u64 key, const void *val,
			     __u64 val__sz) __ksym;

SEC("license") const char __license[] = "GPL";

SEC("socket") int pass(struct __sk_buff *skb)
{
	__u16 val = 0;
	int err = bpf_skb_trait_get(skb, 12, &val, sizeof(val));
	if (err < 0) {
		bpf_printk("SKB: err getting trait 12: %d", err);
		return skb->len;
	}

	bpf_printk("SKB: trait 12 is: %d", val);
	return skb->len;
}
