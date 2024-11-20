// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// clang-format on

struct Data {
	__u32 ip;
	__u64 rx_packets;
	__u64 last_access_ns;
};

static __u64 MS_IN_NS = 100000;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Data);
	__uint(max_entries, 32);
} blacklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Data);
	__uint(max_entries, 32);
} graylist SEC(".maps");

SEC("xdp")
int hpx(struct xdp_md *ctx) {
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

	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	// Extract source IP address
	__u32 src_ip = ip->saddr;

	struct Data *blacklist_data = bpf_map_lookup_elem(&blacklist, &src_ip);
	if (blacklist_data) {
		return XDP_DROP;
	}

	struct Data *graylist_data = bpf_map_lookup_elem(&graylist, &src_ip);
	if (graylist_data) {
		__u64 time = (__u64)1000 * MS_IN_NS;
		if (bpf_ktime_get_ns() - graylist_data->last_access_ns < time) {
			struct Data new = {src_ip, graylist_data->rx_packets,
							   bpf_ktime_get_ns()};

			bpf_map_update_elem(&blacklist, &src_ip, &new, BPF_NOEXIST);

			return XDP_DROP;
		}
		__sync_fetch_and_add(&graylist_data->rx_packets, 1);
		__sync_fetch_and_add(&graylist_data->last_access_ns,
							 bpf_ktime_get_ns() -
								 graylist_data->last_access_ns);

	} else {

		struct Data new = {src_ip, 1, bpf_ktime_get_ns()};
		bpf_map_update_elem(&graylist, &src_ip, &new, BPF_NOEXIST);
	}

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
