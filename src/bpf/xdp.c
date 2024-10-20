// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// clang-format on

struct Data {
    __u32 ip;
    bool ban;
	__u64 rx_packets;
    __u64 last_access_ns;
};

static __u64 MS_IN_NS = 1000000;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Data);
	__uint(max_entries, 32);
} packet_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, bool);
	__uint(max_entries, sizeof(__u64));
} blacklist SEC(".maps");

SEC("xdp")
int hello_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header size
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    // Check IP header size
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    // TODO:
    // 1. Check if the packet is UDP or TCP
    // 2. Decode source port
    // 3. something
    if(ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // Extract source IP address
    __u32 src_ip = ip->saddr;

    if (((struct Data *)bpf_map_lookup_elem(&blacklist, &src_ip))->ban) {
        return XDP_DROP;
    }

    bpf_printk("Received packet from IP: %d.%d.%d.%d\nPort: %d",
               (src_ip >> 0) & 0xFF,
               (src_ip >> 8) & 0xFF,
               (src_ip >> 16) & 0xFF,
               (src_ip >> 24) & 0xFF,
               8080 // need to learn to work with tcp packets
    );

    struct Data *ip_data = bpf_map_lookup_elem(&packet_count, &src_ip);

    if (ip_data) {
        __u64 time = (__u64)2000 * MS_IN_NS;
        if (bpf_ktime_get_ns() - ip_data->last_access_ns < time) {
            bool ban = true;
            bpf_map_update_elem(&blacklist, &src_ip, &ban, BPF_NOEXIST);
        }
        __sync_fetch_and_add(&ip_data->rx_packets, 1);
        __sync_fetch_and_add(&ip_data->last_access_ns, bpf_ktime_get_ns() - ip_data->last_access_ns);
    } else {
        struct Data new = {1, bpf_ktime_get_ns()};
        bpf_map_update_elem(&packet_count, &src_ip, &new, BPF_NOEXIST);
    }

    return XDP_PASS;
}


char __license[] SEC("license") = "GPL";
