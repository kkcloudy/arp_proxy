/*
 * ARP snooping for ARP Proxy
 * Copyright (c) 2016, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include "common.h"
#include "debug.h"
#include "l2_packet.h"
#include "arp_proxy.h"
#include "arp_snoop.h"
#include "arpp_tbl.h"


struct arp_pkt {
	struct ethhdr ethh;
	struct ether_arp arph;
} STRUCT_PACKED;


#define DHCPACK	5
static const u8 ic_bootp_cookie[] = { 99, 130, 83, 99 };
extern int golbal_arp_proxy_switch;
void printPacketBuffer(unsigned char *buffer,unsigned long buffLen)
{
	unsigned int i;

	if(!buffer)
		return;
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
	
	for(i = 0;i < buffLen ; i++)
	{
		arpp_printf(ARPP_DEBUG, "%02x ",buffer[i]);
		if(0==(i+1)%16) {
			arpp_printf(ARPP_DEBUG, "\n");
		}
	}
	if((buffLen%16)!=0)
	{
		arpp_printf(ARPP_DEBUG, "\n");
	}
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
}

static const char * ipaddr_str(u32 addr)
{
	static char buf[17];

	os_snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	return buf;
}

void arp_pkt_print(const struct arp_pkt *p)
{
	if (NULL == p)
		return ;
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");
	arpp_printf(ARPP_DEBUG, "ethh.h_dest: " MACSTR "\n", MAC2STR(p->ethh.h_dest));
	arpp_printf(ARPP_DEBUG, "ethh.h_source: " MACSTR "\n", MAC2STR(p->ethh.h_source));
	arpp_printf(ARPP_DEBUG, "ethh.h_proto: %04x\n", p->ethh.h_proto);

	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_hrd: %02x\n", p->arph.ea_hdr.ar_hrd);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_pro: %02x\n", p->arph.ea_hdr.ar_pro);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_hln: %04x\n", p->arph.ea_hdr.ar_hln);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_pln: %04x\n", p->arph.ea_hdr.ar_pln);
	arpp_printf(ARPP_DEBUG, "arph.ea_hdr.ar_op: %02x\n", p->arph.ea_hdr.ar_op);

	arpp_printf(ARPP_DEBUG, "arph.arp_sha: " MACSTR "\n", MAC2STR(p->arph.arp_sha));
	arpp_printf(ARPP_DEBUG, "arph.arp_spa: %d.%d.%d.%d\n", p->arph.arp_spa[0], 
														p->arph.arp_spa[1],
														p->arph.arp_spa[2],
														p->arph.arp_spa[3]);
	arpp_printf(ARPP_DEBUG, "arph.arp_tha: " MACSTR "\n", MAC2STR(p->arph.arp_tha));
	arpp_printf(ARPP_DEBUG, "arph.arp_tpa: %d.%d.%d.%d\n",  p->arph.arp_tpa[0], 
														p->arph.arp_tpa[1],
														p->arph.arp_tpa[2],
														p->arph.arp_tpa[3]);
	arpp_printf(ARPP_DEBUG, ":::::::::::::::::::::::::::::::::::::::::::::::\n");

	return ;
}


int l2_arp_snoop_init(struct arpp_interfaces *interfaces)
{
	struct l2_packet_data *l2;

	l2 = l2_packet_part_init(NULL, NULL, ETH_P_ARP, NULL, interfaces, 0);
	if (l2 == NULL) {
		arpp_printf(ARPP_DEBUG,
			   "arp_snoop: Failed to initialize L2 packet processing %s",
			   strerror(errno));
		return -1;
	}

	interfaces->l2 = l2;

	return 0;
}

void l2_arp_snoop_deinit(struct arpp_interfaces *interfaces)
{
	if(interfaces->l2) 
		l2_packet_deinit(interfaces->l2);
}
