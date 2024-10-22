#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/time.h>

#define DELAY_NS 500000000  // Delay 500 milliseconds (500ms = 500,000,000 nanoseconds)

struct packet_data {
    struct __sk_buff *skb;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // Use a simple packet identifier
    __type(value, struct bpf_timer);
} packet_timers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // Use a simple packet identifier
    __type(value, struct packet_data);
} delayed_packets SEC(".maps");

// Timer callback to reinject the packet
static void reinject_packet(void *ctx, int *key)
{
    struct packet_data *pkt = bpf_map_lookup_elem(&delayed_packets, key);

    if (pkt && pkt->skb) {
        // Allow the previously dropped packet to pass
        bpf_clone_redirect(pkt->skb, pkt->skb->ifindex, 0);
        
        // Clean up: remove the packet and timer from the maps
        bpf_map_delete_elem(&delayed_packets, key);
        bpf_map_delete_elem(&packet_timers, key);
    }
}

SEC("tc")
int delay_packets(struct __sk_buff *skb)
{
    // Use skb->hash as a unique key for each packet
    __u32 packet_key = skb->hash;

    // Check if there's already a timer for this packet
    struct bpf_timer *timer = bpf_map_lookup_elem(&packet_timers, &packet_key);
    if (!timer) {
        // Set up packet data to be reinjected later
        struct packet_data pkt_data = {
            .skb = skb,
        };
        bpf_map_update_elem(&delayed_packets, &packet_key, &pkt_data, BPF_ANY);

        // Initialize a new timer
        struct bpf_timer new_timer;
        bpf_timer_init(&new_timer, &packet_timers, CLOCK_MONOTONIC);

        // Set the timer callback and start the delay
        bpf_timer_set_callback(&new_timer, reinject_packet);
        bpf_timer_start(&new_timer, DELAY_NS, 0);

        // Save the timer in the map
        bpf_map_update_elem(&packet_timers, &packet_key, &new_timer, BPF_ANY);

        // Drop the packet temporarily  
        return TC_ACT_SHOT;
    }

    // Timer is already set, allow the packet to pass
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

// clang -O2 -g -target bpf -c delay_packets.c -o delay_packets.o


// # Attach the program to the ingress hook of the interface
// sudo tc qdisc add dev lo clsact
// sudo tc filter add dev lo ingress bpf da obj delay_packets.o sec tc
