// dns_delay.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// Define an upper bound for loop iterations
#define MAX_ITERATIONS 1 << 12

// // Map to store delay configuration and spinlock
// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, __u32);
// } delay_config SEC(".maps");

SEC("classifier")
int dns_delay(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    // Check if we have a complete Ethernet header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;
        
    // Check if it's IP
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;
        
    // Check IP header
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;
        
    // Check if it's UDP
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
        
    // Check UDP header
    struct udphdr *udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end)
        return TC_ACT_OK;
        
    // Check if it's DNS (port 53)
    if (udp->dest != __constant_htons(53) && udp->source != __constant_htons(53))
        return TC_ACT_OK;
        
    // Get configured delay
    __u32 delay_ms = 50000;
    if (!delay_ms)
        return TC_ACT_OK;
    
    // Simulate delay using busy wait
    unsigned long start = bpf_ktime_get_ns();
    unsigned long delay_ns = delay_ms * 1000000;
    unsigned int iter_count = 0;

    while (bpf_ktime_get_ns() - start < delay_ns && (iter_count < MAX_ITERATIONS) ) {
        // Busy wait
        iter_count++;
    }
    bpf_printk("Busy wait iterations: %u\n", iter_count);
    // bpf_printk("bpf_ktime_get_ns() - start: %lu\n", bpf_ktime_get_ns() - start);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";