#include "vmlinux.h"

struct Data {
	__u64 rx_packets;
    __u64 last_access_ns;
};

static __u64 SEC_IN_NS = 1000000000;
