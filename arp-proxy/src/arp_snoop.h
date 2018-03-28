/*
 * ARP Proxy
 * Copyright (c) 2014, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef ARP_SNOOP_H
#define ARP_SNOOP_H

void printPacketBuffer(unsigned char *buffer,unsigned long buffLen);
int l2_arp_snoop_init(struct arpp_interfaces *interfaces);
void l2_arp_snoop_deinit(struct arpp_interfaces *interfaces);

#endif /* ARP_SNOOP_H */

