/*
 * arp-proxy / Initialization and configuration
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef ARP_PROXY_H
#define ARP_PROXY_H

#define ARPP_OUT_FILE "/tmp/log/arp-proxy.log"
#define ARPP_INTERFACE_FILE "/var/run/arpp/if_list"
#define ARPP_PID_FILE "/var/run/arpp/arpp.pid"

#define ARPP_FILE_DIR "/var/run/arpp/"
#define ARPP_CTRL_IFACE_PATH "/var/run/arpp/arpp_ctrl"
#define ARPP_DATABASE_IFACE_PATH "/var/run/arpp/arpp_db"

#define MAX_SSID_LEN (32)
#define NETLINK_ARPPM 30
#define ARP_PKT_MIN_LEN 42

#define MAX_PAYLOAD 1024

struct arpp_interfaces {
	size_t count;
	char *ctrl_iface_path;
	int ctrl_iface_sock;
	char *database_iface_path;
	int database_iface_sock;
	int nfq_sock;
	int ioctl_sock;
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct arpp_iface **iface;
	struct l2_packet_data *l2;
};

struct arpp_interfaces *arp_interfaces;

/**
 * struct hostapd_iface - hostapd per-interface data structure
 */
struct arpp_iface {
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	u8 addr[ETH_ALEN];
	be32 ipaddr;

	struct l2_packet_data *sock_arp;
};

typedef enum{
	STA_ADD = 0,
	STA_DEL = 1,
	ARPP_ENABLE = 10,
	ARPP_DISABLE = 11,
	ARPP_CONFIG = 12,
}Operate;

typedef struct {
	Operate op;
	char iface[IFNAMSIZ + 1];
	char bridge[IFNAMSIZ + 1];
	u8 addr[6];
	unsigned int ip_addr;
	char ssid[MAX_SSID_LEN + 1];
	unsigned int lease_time;
}WAM_MSG;

struct arppm_nl_msg
{
	char ifname[IFNAMSIZ];
	u8 arp_req_pkt[ARP_PKT_MIN_LEN];
};


void printPacketBuffer(unsigned char *buffer,unsigned long buffLen);
int linux_br_get(char *brname, const char *ifname);

int arpp_database_iface_init(struct arpp_interfaces *interfaces);
void arpp_database_iface_deinit(struct arpp_interfaces *interfaces);

int arpp_nfqueue_iface_init(struct arpp_interfaces *interfaces);
void arpp_nfqueue_iface_denit(struct arpp_interfaces *interfaces);
int arpp_find_iface(struct arpp_interfaces *interfaces, char *buf, unsigned int *id);
int arpp_add_iface(struct arpp_interfaces *interfaces, char *buf);
int arpp_remove_iface(struct arpp_interfaces *interfaces, char *buf);

#endif
