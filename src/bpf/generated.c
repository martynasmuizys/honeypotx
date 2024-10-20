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

static __u64 MS_IN_NS = 100000;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Data);
	__uint(max_entries, 32);
} whitelist SEC(".maps");

SEC("xdp")
int bananer(struct xdp_md *ctx) {
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

	// Extract source IP address
	__u32 src_ip = ip->saddr;

	struct Data *whitelist_data = bpf_map_lookup_elem(&whitelist, &src_ip);
	if (whitelist_data) {
		return XDP_PASS;
	}

	// Collect data about graylist?
	// apply frequency actions?

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
