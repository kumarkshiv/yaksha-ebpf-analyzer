/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct hdr_cursor
{
    void *pos;
};

struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key,         __u32);
    __type(value,       __u8);
} blocked_ports SEC(".maps");

/* ── Incremental TCP checksum helper (RFC 1624) ───────────────────────────── *
 *  Must be called BEFORE the field is overwritten so old_val is still live.  *
 *  new_cksum = ~(~old_cksum + ~old_val + new_val)                            */
static __always_inline void tcp_csum_replace16(struct tcphdr *tcp,
                                               __be16 old_val,
                                               __be16 new_val)
{
    __u32 csum = (__u16)~tcp->check;
    csum += (__u16)~old_val;
    csum += (__u16)new_val;

    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);

    tcp->check = (__be16)~csum;
}

/*++++++++++++++++++++++++++ Parsing Ethernet Packets+++++++++++++++++++++++++++*/
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return bpf_htons(eth->h_proto);
}

/*+++++++++++++++++++++++++++++ Parsing IP Packets ++++++++++++++++++++++++++++*/
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;

    if (iph + 1 > data_end)
        return -1;

    nh->pos = iph + 1;
    *iphdr = iph;

    return (iph->protocol);
}

/*+++++++++++++++++++++++++++++ Parsing IPV6 Packets ++++++++++++++++++++++++++++*/
static __always_inline int parse_ipv6hdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct ipv6hdr **ipv6hdr)
{
    struct ipv6hdr *ipv6h = nh->pos;

    if (ipv6h + 1 > data_end)
        return -1;

    nh->pos = ipv6h + 1;
    *ipv6hdr = ipv6h;

    return (ipv6h->nexthdr);
}

/*+++++++++++++++++++++++++++++ Parsing TCP Packets ++++++++++++++++++++++++++++*/
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct tcphdr **tcphdr)
{
    struct tcphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos = h + 1;
    *tcphdr = h;

    /* ── Port rewrite: 8080 → 8081 ──────────────────────────────────────── *
     *  1. Fix checksum FIRST (old_val is still live in the packet)          *
     *  2. Then overwrite the field                                          */
    if (h->dest == bpf_htons(8080)) {
        __be16 old_port = h->dest;
        __be16 new_port = bpf_htons(8081);

        tcp_csum_replace16(h, old_port, new_port); /* fix checksum first … */
        h->dest = new_port;                        /* … then rewrite field  */

        bpf_printk("xdp_parser: rewrote dst_port 8080 -> 8081\n");
    }

    return bpf_htons(h->dest);
}

/*+++++++++++++++++++++++++++++ Parsing UDP Packets ++++++++++++++++++++++++++++*/
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
    struct udphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos = h + 1;
    *udphdr = h;

    return bpf_htons(h->source);
}

SEC("xdp")
int xdp_fw_malicious(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct ipv6hdr *ipv6h;

    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;

    nh_type = parse_ethhdr(&nh, data_end, &eth);

    if (nh_type == ETH_P_IP)
    {
        __u_char next_header;
        int port;
        next_header = parse_iphdr(&nh, data_end, &iph);
        if (next_header == IPPROTO_TCP)
        {
            port = parse_tcphdr(&nh, data_end, &tcph);

            __u8 *blocked = bpf_map_lookup_elem(&blocked_ports, &port);
            if (blocked && *blocked) {
                return XDP_DROP;
            }
        }
        else
        {
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
