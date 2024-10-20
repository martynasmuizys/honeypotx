/// Base template
pub static BASE: &str = "// clang-format off
#include \"vmlinux.h\"
#include <bpf/bpf_helpers.h>
// clang-format on

struct Data {
    __u32 ip;
    bool ban;
	__u64 rx_packets;
    __u64 last_access_ns;
};

static __u64 MS_IN_NS = 100000;

{{whitelist_map}}

{{blacklist_map}}

{{graylist_map}}

SEC(\"xdp\")
int {{name}}(struct xdp_md *ctx) {
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

    {{whitelist_action}}

    {{blacklist_action}}

    // Collect data about graylist?
    // apply frequency actions?

    return XDP_PASS;
}


char __license[] SEC(\"license\") = \"GPL\";
";

/// Map template
pub static MAP: &str = "struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Data);
	__uint(max_entries, {{max}});
} {{name}} SEC(\".maps\");
";

/// Allow/Deny action
pub static ACTION: &str = "struct Data *{{list}}_data = bpf_map_lookup_elem(&{{list}}, &src_ip);
	if ({{list}}_data) {
		return {{action}};
	}
";

/// Investigate action
pub static INVESTIGATE: &str = "struct Data *ip_data = bpf_map_lookup_elem(&{{list}}, &src_ip);

if (ip_data) {
    __u64 time = (__u64){{frequency}} * MS_IN_NS;
    if (bpf_ktime_get_ns() - ip_data->last_access_ns < time) {
        bool ban = true;
        bpf_map_update_elem(&{{list}}, &src_ip, &ban, BPF_NOEXIST);
    }
    __sync_fetch_and_add(&ip_data->rx_packets, 1);
    __sync_fetch_and_add(&ip_data->last_access_ns, bpf_ktime_get_ns() - ip_data->last_access_ns);
} else {
    struct Data new = {1, bpf_ktime_get_ns()};
    bpf_map_update_elem(&{{list}}, &src_ip, &new, BPF_NOEXIST);
}
";
