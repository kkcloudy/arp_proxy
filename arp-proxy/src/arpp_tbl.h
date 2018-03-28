/*
 * arp-proxy / hash_table 
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef ARPP_TBL_H
#define ARPP_TBL_H

#define ARPP_ITEM_HASH_TABLE_SIZE 1024
#define ARPP_ITEM_DEFAULT_LEASE_TIME 43200

typedef struct arpp_item_s
{
	struct arpp_item_s *next;
	struct arpp_item_s *hnext;
	unsigned int  bind_type;
	unsigned char state;
	unsigned char haddr_len;
	unsigned char chaddr[ETH_ALEN];
	unsigned short vlanId;
	unsigned int ip_addr;
	unsigned int lease_time;
	unsigned int sys_escape; /*添加绑定表项时系统启动以来所过的时间 */
	unsigned int cur_expire;	   /* 当前使用的有效的IP地址状态超时时间,仅显示时使用*/
	unsigned int ifindex;
	unsigned int flags;
	char iface[IFNAMSIZ + 1];
}arpp_item_t;

arpp_item_t *arpp_item_hash_table[ARPP_ITEM_HASH_TABLE_SIZE];
void *arpp_tbl_item_new_from_msg(WAM_MSG *msg);
int arpp_tbl_item_debug_show(void);
int arpp_tbl_iface_debug_show(struct arpp_interfaces *interfaces);
void arpp_tbl_item_remove(arpp_item_t *item);
void arpp_tbl_item_expire(void *eloop_ctx, void *timeout_ctx);
void arpp_tbl_item_set_expiration(void);
int arpp_tbl_item_insert(arpp_item_t *item);
arpp_item_t *arpp_tbl_item_find_by_ip(unsigned int ipaddr);
#endif
