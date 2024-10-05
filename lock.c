//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct shared_data {
    struct bpf_spin_lock lock;   // spinlock to protect the data
    __u32 counter;                 // shared counter
    __u64 last_updated;          // timestamp of last update
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct shared_data);
    __uint(max_entries, 1);
} shared_map SEC(".maps");

SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
    __u32 key = 0;
    struct shared_data *data;

    // Get the shared data from the map
    data = bpf_map_lookup_elem(&shared_map, &key);
    if (!data) {
        return XDP_ABORTED;
    }

    __u64 time = bpf_ktime_get_ns(); // Get the current time

    // Acquire the spinlock
    bpf_spin_lock(&data->lock);

    // Safely update both fields
    data->counter += 1;
    data->last_updated = time;

    // Release the spinlock
    bpf_spin_unlock(&data->lock);

    bpf_printk("Counted %d times...", data->counter);

    return XDP_PASS;
}
