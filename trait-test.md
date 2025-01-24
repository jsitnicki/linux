# Testing XDP to SKB trait propagation

* Build an XDP program that sets a trait, `trait_set_xdp.c`:

```
clang-16 -target bpf -mcpu=v3 -O2 -g -nostdinc -Wall -Werror -Iheaders/upstream -Iheaders -c trait_set_xdp.c -o trait_set_xdp.elf
```

* Build a socket filter that gets the same trait, `trait_get_sk.c`:

```
clang-16 -target bpf -mcpu=v3 -O2 -g -nostdinc -Wall -Werror -Iheaders/upstream -Iheaders -c trait_get_sk.c -o trait_get_sk.elf
```

* Run the kernel with networking:

```
vng -r arch/x86/boot/bzImage --memory 2G -n user
```

* Load the programs, and generate some traffic:

```
echo "1" | sudo tee /sys/kernel/debug/tracing/tracing_on
sudo ip link set dev eth0 xdp object trait_set_xdp.elf section xdp


sudo ./tools/bpf/bpftool/bpftool prog load trait_get_sk.elf /sys/fs/bpf/trait_get_sk type socket
sudo iptables-legacy -A INPUT -m bpf --object-pinned /sys/fs/bpf/trait_get_sk

curl google.com
```

* `sudo cat /sys/kernel/debug/tracing/trace_pipe` should be full of:

```
          <idle>-0       [003] ..s2.     6.829675: bpf_trace_printk: XDP: trait 12 set to 3456
          <idle>-0       [003] b.s21     6.829686: bpf_trace_printk: SKB: trait 12 is: 3456
```
