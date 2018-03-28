#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_bridge.h>
struct    ether_arp {
	struct arphdr ea_hdr;        /* fixed-size header */
	u_int8_t arp_sha[ETH_ALEN];    /* sender hardware address */
	u_int8_t arp_spa[4];        /* sender protocol address */
	u_int8_t arp_tha[ETH_ALEN];    /* target hardware address */
	u_int8_t arp_tpa[4];        /* target protocol address */
};
#define IS_ARP(skb) ( skb->protocol == htons(ETH_P_ARP))

int arppm_switch = 0;
module_param(arppm_switch,int,0644);
int arppm_debug = 0;
module_param(arppm_debug,int,0644);

void printPacketBuffer(unsigned char *buffer,unsigned long buffLen)
{
         unsigned int i;
 
         if(!buffer)
                 return;
         printk(":::::::::::::::::::::::::::::::::::::::::::::::\n");
         
         for(i = 0;i < buffLen ; i++)
         {
                 printk("%02x ",buffer[i]);
                 if(0==(i+1)%16) {
                         printk("\n");
                 }
         }
         if((buffLen%16)!=0)
         {
                 printk("\n");
         }
         printk(":::::::::::::::::::::::::::::::::::::::::::::::\n");
}

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum,
struct sk_buff *skb,
const struct net_device *in,
const struct net_device *out,
int (*okfn)(struct sk_buff *))
{
	struct ether_arp *arp;
	struct arphdr *arph;
	
	if(skb == NULL)
		printk("####skb is NULL####");
	
	if (!IS_ARP(skb)) {
                return NF_ACCEPT;
        }
	if(arppm_debug)
		printk("####receive arp packe#####\n");
	
	arph = (struct arphdr *)skb->data;
	if(arppm_debug) {
		printPacketBuffer(skb->data,skb->len);
		int i, hlen = 6, iplen = 4;
		arp = (struct ether_arp *)skb->data;
		printk("arp_ethhdr_dest = ");
		for (i = 0; i < hlen-1; i++)
			printk("%02x:", arp->arp_tha[i]);
		printk("%02x ", arp->arp_tha[hlen-1]);
		
		printk("arp_ethhdr_source = ");
		for (i = 0; i < hlen-1; i++)
			printk("%02x:", arp->arp_sha[i]);
		printk( "%02x \n", arp->arp_sha[hlen-1]);
	
		printk("ip_dest = ");
		for (i = 0; i < iplen-1; i++)
			printk("%d:", arp->arp_tpa[i]);
		printk("%d ", arp->arp_tpa[iplen-1]);
	
		printk("ip_source = ");
		for (i = 0; i < iplen-1; i++)
			printk("%d:", arp->arp_spa[i]);
		printk("%d \n", arp->arp_spa[iplen-1]);
		printk("arph->ar_op = 0x%04x, arppm_switch = %d\n", ntohs(arph->ar_op), arppm_switch);
	}
	if (ntohs(arph->ar_op) == 0x0001 && arppm_switch == 1) {
		if(arppm_debug)
			printk("return NF_QUEUE\n");
		return NF_QUEUE;
	} else {
		if(arppm_debug)
			printk("return NF_ACCEPT\n");
		return NF_ACCEPT;
	}

}

int init_module()
{
	nfho.hook = hook_func;
        nfho.hooknum = NF_BR_PRE_ROUTING;
        nfho.pf = NFPROTO_BRIDGE;
        nfho.priority = NF_BR_PRI_BRNF - 1;
	nf_register_hook(&nfho);
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&nfho);
}
