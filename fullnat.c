/* Copyright 2014 yiyuanzhong@gmail.com (Yiyuan Zhong)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/tcp.h>
#include <net/udp.h>

#define RIP_HOOKNUM_INPUT   NF_INET_LOCAL_IN
#define RIP_HOOKNUM_OUTPUT  NF_INET_LOCAL_OUT

/* Avoid those in enum ip_conntrack_status. */
#define RIP_STATUS_NEEDED_BIT 14

static const __be32 kReal = htonl(0xC0A8F380); /* 192.168.243.128 */
static const __be32 kFake = htonl(0xC0A80307); /* 192.168.3.7 */

struct rip_order {
    __be32 faddr;
    __be32 taddr;
    __be16 fport;
    __be16 tport;
};

static inline struct iphdr *rip_ip_hdr(struct sk_buff *skb)
{
    return (struct iphdr *)skb_network_header(skb);
}

static inline struct tcphdr *rip_tcp_hdr(struct sk_buff *skb)
{
    struct iphdr *iph = rip_ip_hdr(skb);
    return (struct tcphdr *)((char *)iph + iph->ihl * 4);
}

static inline struct udphdr *rip_udp_hdr(struct sk_buff *skb)
{
    struct iphdr *iph = rip_ip_hdr(skb);
    return (struct udphdr *)((char *)iph + iph->ihl * 4);
}

static unsigned int rip_manipulate_tcp(struct sk_buff *skb,
                                       struct rip_order *order,
                                       bool snat_or_dnat)
{
    struct tcphdr *tcp;
    struct iphdr *iph;
    struct rtable *rt;
    int datalen;
    int hdrlen;
    int hdroff;

    if (!skb_make_writable(skb, skb->len)) {
        return NF_DROP;
    }

    iph = rip_ip_hdr(skb);
    tcp = rip_tcp_hdr(skb);

    if (snat_or_dnat) {
        iph->saddr = order->taddr;
        tcp->source = order->tport;

    } else {
        iph->daddr = order->taddr;
        tcp->dest = order->tport;

        /* Maybe I need to rewire. */
        if (ip_route_me_harder(skb, RTN_UNSPEC)) {
            return NF_DROP;
        }
    }

    /* Guaranteed length. */
    hdrlen = 8;
    hdroff = skb_network_offset(skb) + iph->ihl * 4;
    if (skb->len >= hdroff + sizeof(struct tcphdr)) {
        hdrlen = sizeof(struct tcphdr);
    }

    /* Calculate IP checksum. */
    ip_send_check(iph);

    /* TCP header inside a returned ICMP packet. */
    if (hdrlen < sizeof(struct tcphdr)) {
        return NF_ACCEPT;
    }

    /* Calculate TCP checksum. */
    rt = skb_rtable(skb);
    datalen = skb->len - iph->ihl * 4;
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        inet_proto_csum_replace4(&tcp->check, skb, order->faddr, order->taddr, 1);
        inet_proto_csum_replace2(&tcp->check, skb, order->fport, order->tport, 0);

    /* The packet is not for loopback so skip checking routing table. */
    } else if (rt && !(rt->rt_flags & RTCF_LOCAL) &&
               skb->dev && (skb->dev->features & NETIF_F_V4_CSUM)) {

        skb->ip_summed = CHECKSUM_PARTIAL;
        skb->csum_start = skb_headroom(skb) + skb_network_offset(skb) + iph->ihl * 4;
        skb->csum_offset = offsetof(struct tcphdr, check);
        tcp->check = ~tcp_v4_check(datalen, iph->saddr, iph->daddr,
                                   csum_partial(tcp, datalen, 0));

    } else {
        tcp->check = 0;
        tcp->check = tcp_v4_check(datalen, iph->saddr, iph->daddr,
                                  csum_partial(tcp, datalen, 0));
    }

    return NF_ACCEPT;
}

static bool rip_get_order_input_tcp(struct sk_buff *skb, struct rip_order *order)
{
    struct nf_conntrack_tuple *original;
    struct nf_conntrack_tuple *reply;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *nfct;

    nfct = nf_ct_get(skb, &ctinfo);
    if (!nfct) {
        return false;
    }

    original = &nfct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    reply = &nfct->tuplehash[IP_CT_DIR_REPLY].tuple;
    order->faddr = original->src.u3.ip;
    order->fport = original->src.u.tcp.port;
    order->taddr = reply->dst.u3.ip;
    order->tport = reply->dst.u.tcp.port;
    return true;
}

static bool rip_get_order_output_tcp(struct sk_buff *skb, struct rip_order *order)
{
    struct nf_conntrack_tuple *original;
    struct nf_conntrack_tuple *reply;
    enum ip_conntrack_info ctinfo;
    struct nf_conn *nfct;

    nfct = nf_ct_get(skb, &ctinfo);
    if (!nfct) {
        return false;
    }

    original = &nfct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    reply = &nfct->tuplehash[IP_CT_DIR_REPLY].tuple;
    order->faddr = reply->dst.u3.ip;
    order->fport = reply->dst.u.tcp.port;
    order->taddr = original->src.u3.ip;
    order->tport = original->src.u.tcp.port;
    return true;
}

static int rip_needed_tcp(struct sk_buff *skb, struct rip_order *order)
{
    struct tcphdr *tcp;
    struct iphdr *iph;

    /* I need to dereference TCP header so make it linear. */
    iph = rip_ip_hdr(skb);
    if (!skb_make_writable(skb, skb_network_offset(skb) + iph->ihl * 4 + 8)) {
        return -1;
    }

    iph = rip_ip_hdr(skb);
    tcp = rip_tcp_hdr(skb);

    /* TODO(yiyuanzhong): extract original information here. */
    if (iph->saddr != kReal) {
        return 1;
    }

    order->faddr = iph->saddr;
    order->taddr = kFake;
    order->fport = tcp->source;
    order->tport = tcp->source;

    /* Check again. */
    if (unlikely(order->faddr == order->taddr && order->fport == order->tport)) {
        return 1;
    }

    return 0;
}

static unsigned int rip_hook_input_tcp(struct sk_buff *skb)
{
    struct nf_conntrack_tuple *reply;
    struct nf_conntrack_tuple tuple;
    enum ip_conntrack_info ctinfo;
    struct rip_order order;
    struct nf_conn *nfct;
    int ret;

    nfct = nf_ct_get(skb, &ctinfo);
    if (!nfct) {
        return NF_ACCEPT;
    }

    if (test_bit(RIP_STATUS_NEEDED_BIT, &nfct->status)) {
        /* Connection that is being manipulated. */
        if (!rip_get_order_input_tcp(skb, &order)) {
            return NF_DROP;
        }

    } else if (ctinfo != IP_CT_NEW && ctinfo != IP_CT_RELATED) {
        /* Existing connection not being manipulated. */
        return NF_ACCEPT;

    } else {
        /* New connection. */
        ret = rip_needed_tcp(skb, &order);
        if (ret < 0) {
            return NF_DROP;
        } else if (ret > 0) {
            return NF_ACCEPT;
        }

        /* Activate the output hook. */
        set_bit(RIP_STATUS_NEEDED_BIT, &nfct->status);

        /* Make sure conntrack can translate the packet back. */
        reply = &nfct->tuplehash[IP_CT_DIR_REPLY].tuple;
        tuple = *reply;
        tuple.dst.u3.ip = kFake;
        nf_conntrack_alter_reply(nfct, &tuple);
    }

    return rip_manipulate_tcp(skb, &order, true);
}

static unsigned int rip_hook_input_udp(struct sk_buff *skb)
{
    return NF_ACCEPT;
}

static unsigned int rip_hook_output_tcp(struct sk_buff *skb)
{
    enum ip_conntrack_info ctinfo;
    struct rip_order order;
    struct nf_conn *nfct;

    nfct = nf_ct_get(skb, &ctinfo);
    if (!nfct) {
        return NF_ACCEPT;
    }

    if (!test_bit(RIP_STATUS_NEEDED_BIT, &nfct->status)) {
        return NF_ACCEPT;
    }

    if (!rip_get_order_output_tcp(skb, &order)) {
        return NF_DROP;
    }

    return rip_manipulate_tcp(skb, &order, false);
}

static unsigned int rip_hook_output_udp(struct sk_buff *skb)
{
    return NF_ACCEPT;
}

static unsigned int rip_inet_hook(unsigned int hook,
                                  struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    unsigned int ret;

    if (!skb) {
        return NF_ACCEPT;
    }

    iph = rip_ip_hdr(skb);
    if (!iph) {
        return NF_ACCEPT;
    }

    ret = NF_ACCEPT;
    if (hook == RIP_HOOKNUM_INPUT) {
        if (iph->protocol == IPPROTO_TCP) {
            ret = rip_hook_input_tcp(skb);
        } else if (iph->protocol == IPPROTO_UDP) {
            ret = rip_hook_input_udp(skb);
        }
    } else if (hook == RIP_HOOKNUM_OUTPUT) {
        if (iph->protocol == IPPROTO_TCP) {
            ret = rip_hook_output_tcp(skb);
        } else if (iph->protocol == IPPROTO_UDP) {
            ret = rip_hook_output_udp(skb);
        }
    }

    return ret;
}

static struct nf_hook_ops lvshooks[] __read_mostly = {
    {
        .hook = rip_inet_hook,
        .pf = PF_INET,
        .hooknum = RIP_HOOKNUM_INPUT,
        .priority = NF_IP_PRI_MANGLE,
    }, {
        .hook = rip_inet_hook,
        .pf = PF_INET,
        .hooknum = RIP_HOOKNUM_OUTPUT,
        .priority = NF_IP_PRI_MANGLE,
    },
};

static int __init rip_initialize(void)
{
    need_ipv4_conntrack();
    return nf_register_hooks(lvshooks, ARRAY_SIZE(lvshooks));
}

static void __exit rip_shutdown(void)
{
    nf_unregister_hooks(lvshooks, ARRAY_SIZE(lvshooks));
}

module_init(rip_initialize);
module_exit(rip_shutdown);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("yiyuanzhong@gmail.com (Yiyuan Zhong)");
