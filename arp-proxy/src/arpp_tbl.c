/*
 * arp-proxy / hash_table function
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <syslog.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>

#include "common.h"
#include "os.h"
#include "eloop.h"
#include "debug.h"
#include "arp_proxy.h"
#include "arpp_tbl.h"

arpp_item_t *arpp_item_hash_table[ARPP_ITEM_HASH_TABLE_SIZE] = {0};
arpp_item_t *arpp_item_list = NULL;

unsigned int arpp_tbl_ip_hash(unsigned int ipaddr)
{
    return ipaddr % ARPP_ITEM_HASH_TABLE_SIZE;
}

int arpp_tbl_item_debug_show(void)
{
	unsigned int key = 0;
	arpp_item_t *temp_item = arpp_item_list;
	arpp_printf(ARPP_INFO,"-------------------------------------------------\n");
	arpp_printf(ARPP_INFO,"ARP PROXY ITEM:\n");
	while(temp_item) {
		arpp_printf(ARPP_INFO, "%-7s:%02x:%02x:%02x:%02x:%02x:%02x ", 
			"mac", temp_item->chaddr[0], temp_item->chaddr[1],
			temp_item->chaddr[2], temp_item->chaddr[3],
			temp_item->chaddr[4], temp_item->chaddr[5]);
		arpp_printf(ARPP_INFO, "%-7s:%s\n", "ip", u32ip2str(temp_item->ip_addr));
		arpp_printf(ARPP_INFO, "%-7s:%d\n","lease", temp_item->lease_time);
		temp_item = temp_item->next;
	}
	
	arpp_printf(ARPP_INFO,"-------------------------------------------------\n");
	return 0;
}

int arpp_tbl_iface_debug_show(struct arpp_interfaces *interfaces)
{
	int i;
	arpp_printf(ARPP_INFO,"-------------------------------------------------\n");
	arpp_printf(ARPP_INFO,"ARP PROXY IFACE:\n");
	for (i = 0; i < interfaces->count; i++) {
		arpp_printf(ARPP_INFO,"%s\n",interfaces->iface[i]->ifname);	
	}
	arpp_printf(ARPP_INFO,"-------------------------------------------------\n");

	return 0;
}

void *arpp_tbl_item_new_from_msg(WAM_MSG *msg)
{
	arpp_item_t *item = NULL;
	int i;
	struct os_time now;


	item = malloc(sizeof(arpp_item_t));
	if (!item) {
		arpp_printf(ARPP_ERROR, "%s: can not malloc the memory\n", __func__);			
		return NULL;
	}
	memset(item, 0, sizeof(arpp_item_t));
	
	item->ip_addr = ntohl(msg->ip_addr);
	for (i = 0; i < ETH_ALEN; i++) {
		item->chaddr[i] = msg->addr[i];
	}
	os_get_time(&now);
	item->lease_time = msg->lease_time;
	if(item->lease_time)
		item->cur_expire = now.sec + item->lease_time;
	else
		item->cur_expire = now.sec + ARPP_ITEM_DEFAULT_LEASE_TIME;
	os_strncpy(item->iface, msg->iface, IFNAMSIZ + 1);

	return item;
}

arpp_item_t *arpp_tbl_item_find_by_mac(unsigned char *addr)
{
	arpp_item_t *tmp = arpp_item_list;

	while(tmp) {
		if(os_memcmp(tmp->chaddr, addr, ETH_ALEN) == 0)
			return tmp;
		tmp = tmp->next;
	}
	
	return NULL;
}


arpp_item_t *arpp_tbl_item_find_by_ip(unsigned int ipaddr)
{
	unsigned int key = 0;
	arpp_item_t *temp_item = NULL;
	
	if (ipaddr == 0) {
		arpp_printf(ARPP_DEBUG, "%s: error, parameter is null\n", __func__);
		return NULL;
	}
	
	key = arpp_tbl_ip_hash(ipaddr);
	if (key >= ARPP_ITEM_HASH_TABLE_SIZE) {
		arpp_printf(ARPP_ERROR, "%s: error in calculate the hash value %d, ip %#x\n", __func__, key, ipaddr);
		return NULL;
	}

	temp_item = arpp_item_hash_table[key];
	while (temp_item) {
		if (temp_item->ip_addr == ipaddr) {
			arpp_printf(ARPP_INFO, "found item by ip " MACSTR " %s\n", 
					MAC2STR(temp_item->chaddr), u32ip2str(temp_item->ip_addr));
			
			break;
		}
		temp_item = temp_item->hnext;
	}
	
	return temp_item;
}

static void arpp_tbl_item_hash_del(arpp_item_t *item)
{
	unsigned int key = 0;
	arpp_item_t *temp_item = NULL;

	key = arpp_tbl_ip_hash(item->ip_addr);
	
	if (arpp_item_hash_table[key] == item) {
		
		arpp_item_hash_table[key] = item->hnext;
		arpp_printf(ARPP_INFO, "delete table from ip hash " MACSTR " %s\n", 
				MAC2STR(item->chaddr), u32ip2str(item->ip_addr));	
		return;
	}

	temp_item = arpp_item_hash_table[key];
	
	while(temp_item && temp_item->hnext) {
		
		if (temp_item->hnext == item) {
			temp_item->hnext = item->hnext;
			arpp_printf(ARPP_INFO, "delete table from ip hash " MACSTR " %s\n", 
				MAC2STR(item->chaddr), u32ip2str(item->ip_addr));
			return;
		}
		temp_item = temp_item->hnext;
	}

	arpp_printf(ARPP_INFO, "could not delete table from ip hash " MACSTR " %s\n", 
				MAC2STR(item->chaddr), u32ip2str(item->ip_addr));
}

static void arpp_tbl_item_list_del(arpp_item_t *item)
{
	arpp_item_t *temp_item = NULL;
	
	if(arpp_item_list == item) {
		
		arpp_item_list = item->next;		
		arpp_printf(ARPP_INFO, "delete table from ip list " MACSTR " %s\n", 
						MAC2STR(item->chaddr), u32ip2str(item->ip_addr));
		return;
	}
	
	temp_item = arpp_item_list;

	while(temp_item && temp_item->next){

		if (temp_item->next == item) {
			temp_item->next = item->next;
			item->next = NULL;
			arpp_printf(ARPP_INFO, "delete table from ip list " MACSTR " %s\n", 
						MAC2STR(item->chaddr), u32ip2str(item->ip_addr));
			return;
		}
		temp_item = temp_item->next;
	}

	arpp_printf(ARPP_INFO, "could not delete table from ip list " MACSTR " %s\n", 
						MAC2STR(item->chaddr), u32ip2str(item->ip_addr));
}

void arpp_tbl_item_remove(arpp_item_t *item)
{


	if ((NULL == item) || (!item->ip_addr)) {
		arpp_printf(ARPP_ERROR, "%s: error, parameter is null\n", __func__);
		return;
	}

	arpp_tbl_item_hash_del(item);
	arpp_tbl_item_list_del(item);
	os_free(item);
}

void arpp_tbl_item_expire(void *eloop_ctx, void *timeout_ctx)
{
	struct os_time now;
	arpp_printf(ARPP_DEBUG, "now in func arpp_tbl_item_expire\n");
	os_get_time(&now);
	while (arpp_item_list && arpp_item_list->cur_expire <= now.sec) {
		arpp_tbl_item_remove(arpp_item_list);
		arpp_printf(ARPP_DEBUG, "now func arpp_tbl_item_remove end\n");
	}

	arpp_tbl_item_set_expiration();
}


void arpp_tbl_item_set_expiration(void)
{
	int sec;
	struct os_time now;
	arpp_printf(ARPP_DEBUG, "now in func arpp_tbl_item_set_expiration\n");
	
	eloop_cancel_timeout(arpp_tbl_item_expire, NULL, NULL);
	if (arpp_item_list == NULL)
		return;
	os_get_time(&now);
	sec = arpp_item_list->cur_expire - now.sec;
	if (sec < 0)
		sec = 0;
	eloop_register_timeout(sec + 1, 0, arpp_tbl_item_expire, NULL, NULL);
	arpp_printf(ARPP_DEBUG, "now func arpp_tbl_item_set_expiration end\n");
}

int arpp_tbl_item_insert(arpp_item_t *item)
{
	unsigned int key = 0;
	arpp_item_t *tmp = NULL;
	arpp_item_t *prev = NULL;
	
	if ((NULL == item) || (!item->ip_addr)) {
		arpp_printf(ARPP_DEBUG, "%s: error, parameter is null\n", __func__);
		return -1;
	}

	while (tmp = arpp_tbl_item_find_by_ip(item->ip_addr)) {
		arpp_tbl_item_remove(tmp);
		arpp_printf(ARPP_INFO, MACSTR " %s already in ip hash table\n", 
			MAC2STR(tmp->chaddr), u32ip2str(tmp->ip_addr));
		return -1; 
	}

	while (tmp = arpp_tbl_item_find_by_mac(item->chaddr)) {
		arpp_tbl_item_remove(tmp);
		arpp_printf(ARPP_INFO, MACSTR " %s already in arpp item list\n", 
			MAC2STR(tmp->chaddr), u32ip2str(tmp->ip_addr));
	}
	
	key = arpp_tbl_ip_hash(item->ip_addr);
	if (key >= ARPP_ITEM_HASH_TABLE_SIZE)	{
		arpp_printf(ARPP_ERROR, "error in calculate the ip hash value\n");
		return -1;
	}
	item->hnext = arpp_item_hash_table[key];
	arpp_item_hash_table[key] = item;

	tmp = arpp_item_list;

	while(tmp) {
		
		if(tmp->cur_expire > item->cur_expire)
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if(prev == NULL) {
		
		item->next = arpp_item_list;
		arpp_item_list = item;
		
	}else {
		
		item->next = prev->next;
		prev->next = item;
	}

	if(prev == NULL) {
		arpp_tbl_item_set_expiration();
	}
	
    return 0;
}


