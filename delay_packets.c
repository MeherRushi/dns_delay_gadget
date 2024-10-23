#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <linux/time.h>

#define DELAY_NS 500000000  // Delay of 500 milliseconds (500ms = 500,000,000 nanoseconds)
#define MAX_PACKET_SIZE 512 // DNS packets usually fit within 512 bytes

struct packet_data {
    __u32 ifindex;  // Store the interface index
    __u32 len;      // Packet length
    __u8 data[MAX_PACKET_SIZE]; // Store part of the packet (DNS in this case)
};

// Per-CPU array to hold packet data temporarily
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct packet_data);
} pkt_data_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // Packet identifier
    __type(value, struct packet_data);
} delayed_packets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // Packet identifier
    __type(value, struct bpf_timer);
} packet_timers SEC(".maps");

// Timer callback to reinject the packet
static void reinject_packet(void *ctx, int *key)
{
    struct packet_data *pkt = bpf_map_lookup_elem(&delayed_packets, key);

    if (pkt) {
        // Reinject the packet with the stored data
        int result = bpf_clone_redirect(ctx, pkt->ifindex, 0);
        if (result == 0) {
            // Clean up: remove the packet and timer from the maps after successful reinjection
            bpf_map_delete_elem(&delayed_packets, key);
            bpf_map_delete_elem(&packet_timers, key);
        }
    }
}

// Helper function to parse IP and UDP headers
static __always_inline int is_dns_packet(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return 0;  // Drop if the Ethernet header is incomplete
    }

    // Check if this is an IP packet (ETH_P_IP)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return 0;  // Drop if the IP header is incomplete
    }

    // Check if it's a UDP packet (IPPROTO_UDP)
    if (ip->protocol != IPPROTO_UDP) {
        return 0;
    }

    // Parse UDP header
    struct udphdr *udp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(udp + 1) > data_end) {
        return 0;  // Drop if the UDP header is incomplete
    }

    // Check if it's a DNS packet (UDP port 53)
    if (udp->dest == bpf_htons(53) || udp->source == bpf_htons(53)) {
        return 1;  // It's a DNS packet!
    }

    return 0;  // Not a DNS packet
}

SEC("tc")
int delay_packets(struct __sk_buff *skb)
{
    // Check if the packet is a DNS packet
    if (!is_dns_packet(skb)) {
        return TC_ACT_OK;  // Let non-DNS packets pass
    }

    // Use skb->hash as a unique key for each packet
    __u32 packet_key = skb->hash;

    // Check if there's already a timer for this packet
    struct bpf_timer *timer = bpf_map_lookup_elem(&packet_timers, &packet_key);
    if (!timer) {
        // Get a pointer to the per-CPU packet data
        __u32 key = 0;
        struct packet_data *pkt_data = bpf_map_lookup_elem(&pkt_data_array, &key);
        if (!pkt_data) {
            struct packet_data new_pkt_data = {0};
            new_pkt_data.ifindex = skb->ifindex;
            new_pkt_data.len = skb->len > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : skb->len;
            bpf_skb_load_bytes(skb, 0, new_pkt_data.data, new_pkt_data.len);
            bpf_map_update_elem(&pkt_data_array, &key, &new_pkt_data, BPF_ANY);
        }
        else{
            // Fill in the packet data
            pkt_data->ifindex = skb->ifindex;
            pkt_data->len = skb->len > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : skb->len;

            // Copy the DNS packet data (up to MAX_PACKET_SIZE)
            bpf_skb_load_bytes(skb, 0, pkt_data->data, pkt_data->len);

            // Store the packet data in the map
            bpf_map_update_elem(&delayed_packets, &packet_key, pkt_data, BPF_ANY);
        }

        // Initialize and start the timer directly in the map
        struct bpf_timer *new_timer = bpf_map_lookup_elem(&packet_timers, &packet_key);
        if (!new_timer) {
            struct bpf_timer timer_value;
            bpf_timer_init(&timer_value, &packet_timers, CLOCK_MONOTONIC);

            // Set the timer callback and start the delay
            bpf_timer_set_callback(&timer_value, reinject_packet);
            bpf_timer_start(&timer_value, DELAY_NS, 0);

            // Save the timer in the map
            bpf_map_update_elem(&packet_timers, &packet_key, &timer_value, BPF_ANY);

            // Drop the packet temporarily  
            return TC_ACT_SHOT;
        }
    }

    // Timer is already set, allow the packet to pass
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";



// clang -O2 -g -target bpf -c delay_packets.c -o delay_packets.o


// # Attach the program to the ingress hook of the interface
// sudo tc qdisc add dev lo clsact
// sudo tc filter add dev lo ingress bpf da obj delay_packets.o sec tc
