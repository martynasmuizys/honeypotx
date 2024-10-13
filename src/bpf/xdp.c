// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xdp_common.h"
// clang-format on

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Data);
	__uint(max_entries, 32);
} packet_count SEC(".maps");

SEC("xdp")
int hello_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header size
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    struct ethhdr *eth = data;

    // Check IP header size
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_DROP;

    if(ip->protocol != IPPROTO_TCP) {
        return XDP_DROP;
    }

    // Extract source IP address
    __u32 src_ip = ip->saddr;

    bpf_printk("Received packet from IP: %d.%d.%d.%d",
               (src_ip >> 0) & 0xFF,
               (src_ip >> 8) & 0xFF,
               (src_ip >> 16) & 0xFF,
               (src_ip >> 24) & 0xFF);

    struct Data *packets = bpf_map_lookup_elem(&packet_count, &src_ip);

    if (packets) {
        __sync_fetch_and_add(&packets->rx_packets, 1);
    } else {
        struct Data new = {1};
        bpf_map_update_elem(&packet_count, &src_ip, &new, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
