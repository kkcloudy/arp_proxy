/*
 * arp-proxy
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
#include <sys/wait.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <linux/netlink.h>
#include <netinet/in.h>

#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "common.h"
#include "eloop.h"
#include "debug.h"
#include "arp_proxy.h"
#include "l2_packet.h"
#include "arpp_tbl.h"
#include "list.h"

extern int golbal_arp_proxy_switch;

struct arp_pkt {
	struct ethhdr ethh;
	struct ether_arp arph;
} STRUCT_PACKED;

static int handle_nfqueue_arp(struct ether_arp *b, char *ethhdr_saddr)
{
	struct arp_pkt *r;
	arpp_item_t *item = NULL, *s_item = NULL;
	u32 ipaddr = 0, l;
	char *s;
	int i, res;

	if ((b->arp_spa[0] == b->arp_tpa[0]) &&
		(b->arp_spa[1] == b->arp_tpa[1]) &&
		(b->arp_spa[2] == b->arp_tpa[2]) &&
		(b->arp_spa[3] == b->arp_tpa[3])) {
		/* gratuitous arp, ignore */
		return 1;
	}

	ipaddr = ntohl(((b->arp_tpa[0] & 0xff) << 24) | ((b->arp_tpa[1] & 0xff) << 16)
				| ((b->arp_tpa[2] & 0xff) << 8) | ((b->arp_tpa[3] & 0xff) << 0));

	item = arpp_tbl_item_find_by_ip(ipaddr);

	if (NULL == item) {
		arpp_printf(ARPP_DEBUG, "Failed to find user mac by ip %s\n", u32ip2str(ipaddr));
		return 1;
	}
	
	r = os_malloc(sizeof(struct arp_pkt));
	if (NULL == r) {
		arpp_printf(ARPP_ERROR, "%s: Failed to malloc!!!\n", __func__);
		return -1;
	}
	os_memset(r, 0, sizeof(struct arp_pkt));

	os_memcpy(r->ethh.h_dest, ethhdr_saddr, ETH_ALEN);
	os_memcpy(r->ethh.h_source, item->chaddr, ETH_ALEN);
	r->ethh.h_proto = htons(0x0806);
	r->arph.ea_hdr.ar_hrd = htons(0x1);
	r->arph.ea_hdr.ar_pro = htons(0x0800);
	r->arph.ea_hdr.ar_hln = 0x6;
	r->arph.ea_hdr.ar_pln = 0x4;
	r->arph.ea_hdr.ar_op = htons(0x2);
	os_memcpy(r->arph.arp_sha, item->chaddr, ETH_ALEN);
	os_memcpy(r->arph.arp_tha, ethhdr_saddr, ETH_ALEN);
	for (i = 0; i < 4; i++) {
		r->arph.arp_spa[i] = b->arp_tpa[i];
		r->arph.arp_tpa[i] = b->arp_spa[i];
	}

	//arp_pkt_print(r);
	s = os_malloc(sizeof(struct arp_pkt) + 12);
	if (NULL == s) {
		arpp_printf(ARPP_ERROR, "%s: Failed to malloc!!!\n", __func__);
		return -1;
	}
	os_memset(s, 0, sizeof(struct arp_pkt) + 12);

	os_memcpy(s, r, sizeof(struct arp_pkt));
	l = sizeof(struct arp_pkt);
	s[l+1] = 0x11;
	s[l+2] = 0x22;
	s[l+3] = 0x33;

	arpp_printf(ARPP_DEBUG, "l2->ifindex = %d, arp_interfaces->l2->fd= %d\n", arp_interfaces->l2->ifindex, arp_interfaces->l2->fd);
	res = l2_packet_send(arp_interfaces->l2, ethhdr_saddr, ETH_P_ALL,
							(u8 *)s, sizeof(struct arp_pkt) + 12);
	if (res < 0) {
		arpp_printf(ARPP_DEBUG,
			   "%s: Failed to send ARP reply packet to "
			   MACSTR, MAC2STR(r->ethh.h_source));

		return 1;
	}

	arpp_printf(ARPP_DEBUG, "-----------------------------------------------\n");
	arpp_printf(ARPP_DEBUG, "FIND THE IP IN THIS AP !!  IP = ");
	for (i = 0; i < 3; i++)
		arpp_printf(ARPP_DEBUG, "%d.", b->arp_tpa[i]);
	arpp_printf(ARPP_DEBUG, "%d ", b->arp_tpa[3]);
	arpp_printf(ARPP_DEBUG, "ETHADDR = ");
	for (i = 0; i < 5; i++)
		arpp_printf(ARPP_DEBUG, "%02x:", item->chaddr[i]);
	arpp_printf(ARPP_DEBUG, "%02x \n", item->chaddr[5]);

	if (r)
		os_free(r);

	if (s)
		os_free(s);

	return 0;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *arpdata;
	struct ethhdr *ethh;
	struct ether_arp *arph;

	arpp_printf(ARPP_DEBUG, "entering callback\n");

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		arpp_printf(ARPP_DEBUG, "hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(nfa);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		arpp_printf(ARPP_DEBUG, "hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			arpp_printf(ARPP_DEBUG, "%02x:", hwph->hw_addr[i]);
		arpp_printf(ARPP_DEBUG, "%02x ", hwph->hw_addr[hlen-1]);
	}

	ifi = nfq_get_indev(nfa);
	if (ifi)
		arpp_printf(ARPP_DEBUG, "indev=%u ", ifi);
	if (!arp_interfaces->l2) {
		arpp_printf(ARPP_ERROR, "arp_interfaces->l2 is NULL\n");
		return -1;
	}
	arp_interfaces->l2->ifindex = ifi;

	ifi = nfq_get_outdev(nfa);
	if (ifi)
		arpp_printf(ARPP_DEBUG, "outdev=%u ", ifi);

	ret = nfq_get_payload(nfa, &arpdata);
	if (ret >= 0)
		arpp_printf(ARPP_DEBUG, "payload_len=%d ", ret);

	arpp_printf(ARPP_DEBUG, "payload:\n");
	printPacketBuffer(arpdata, ret);
	
	int i, hlen = 6, iplen = 4;
	arph = (struct ether_arp *)arpdata;
	arpp_printf(ARPP_DEBUG, "arp_ethhdr_dest = ");
	for (i = 0; i < hlen-1; i++)
		arpp_printf(ARPP_DEBUG, "%02x:", arph->arp_tha[i]);
	arpp_printf(ARPP_DEBUG, "%02x ", arph->arp_tha[hlen-1]);
		
	arpp_printf(ARPP_DEBUG, "arp_ethhdr_source = ");
	for (i = 0; i < hlen-1; i++)
		arpp_printf(ARPP_DEBUG, "%02x:", arph->arp_sha[i]);
	arpp_printf(ARPP_DEBUG, "%02x \n", arph->arp_sha[hlen-1]);
	
	arpp_printf(ARPP_DEBUG, "ip_dest = ");
	for (i = 0; i < iplen-1; i++)
		arpp_printf(ARPP_DEBUG, "%d:", arph->arp_tpa[i]);
	arpp_printf(ARPP_DEBUG, "%d ", arph->arp_tpa[iplen-1]);
	
	arpp_printf(ARPP_DEBUG, "ip_source = ");
	for (i = 0; i < iplen-1; i++)
		arpp_printf(ARPP_DEBUG, "%d:", arph->arp_spa[i]);
	arpp_printf(ARPP_DEBUG, "%d \n", arph->arp_spa[iplen-1]);


	if (handle_nfqueue_arp(arph, hwph->hw_addr)) {
		arpp_printf(ARPP_DEBUG, "NOT FIND THE IP IN THIS AP, return NF_ACCEPT!!\n\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	} else {
		arpp_printf(ARPP_DEBUG, "return NF_DROP!!\n");
		arpp_printf(ARPP_DEBUG, "-----------------------------------------------\n\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
}


int linux_br_get(char *brname, const char *ifname)
{
	char path[128], brlink[128], *pos;
	os_snprintf(path, sizeof(path), "/sys/class/net/%s/brport/bridge",
		    ifname);
	os_memset(brlink, 0, sizeof(brlink));
	if (readlink(path, brlink, sizeof(brlink) - 1) < 0)
		return -1;
	pos = os_strrchr(brlink, '/');
	if (pos == NULL)
		return -1;
	pos++;
	os_strlcpy(brname, pos, IFNAMSIZ);
	return 0;
}



static void arpp_nfqueue_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
    int res;
    char buf[4096] __attribute__ ((aligned));
	struct arpp_interfaces *arpp_iface = eloop_ctx;

    /* recv msg from kernel */
    res = recv(arpp_iface->nfq_sock, buf, sizeof(buf), 0);
    if (res < 0) {
		if (errno == ENOBUFS) {
			arpp_printf(ARPP_DEBUG, "recv(nfqueue):losing packets!\n");
			return;
		} else {
			arpp_printf(ARPP_ERROR, "recv(nfqueue):recv failed!\n");
			goto fail;
		}
	}

	arpp_printf(ARPP_DEBUG, "pkt received\n");
	nfq_handle_packet(arpp_iface->h, buf, res);

    return;
	
fail:
	arpp_printf(ARPP_DEBUG, "unbinding from queue 0\n");
	nfq_destroy_queue(arpp_iface->qh);
	
#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	arpp_printf(ARPP_DEBUG, "unbinding from NFPROTO_ARP\n");
	nfq_unbind_pf(arpp_iface->h, NFPROTO_ARP);
#endif

	arpp_printf(ARPP_DEBUG, "closing library handle\n");
	nfq_close(arpp_iface->h);

	return;
}

int arpp_nfqueue_iface_init(struct arpp_interfaces *interfaces)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;

	arpp_printf(ARPP_DEBUG, "opening library handle\n");
	h = nfq_open();
	if (!h) {
		arpp_printf(ARPP_ERROR, "error during nfq_open()\n");
		goto fail_open;
	}

	arpp_printf(ARPP_DEBUG, "unbinding existing nf_queue handler for NFPROTO_ARP (if any)\n");
	if (nfq_unbind_pf(h, NFPROTO_ARP) < 0) {
		arpp_printf(ARPP_ERROR, "error during nfq_unbind_pf()\n");
		goto fail_open;
	}

	arpp_printf(ARPP_DEBUG, "binding nfnetlink_queue as nf_queue handler for NFPROTO_ARP\n");
	if (nfq_bind_pf(h, NFPROTO_ARP) < 0) {
		arpp_printf(ARPP_ERROR, "error during nfq_bind_pf()\n");
		goto fail_bind;
	}

	arpp_printf(ARPP_DEBUG, "binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		arpp_printf(ARPP_ERROR, "error during nfq_create_queue()\n");
		goto fail_create;
	}
	
	arpp_printf(ARPP_DEBUG, "setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		arpp_printf(ARPP_ERROR, "can't set packet_copy mode\n");
		goto fail_create;
	}
	fd = nfq_fd(h);
	interfaces->nfq_sock = fd;
	interfaces->h = h;
	interfaces->qh = qh;
	
	eloop_register_read_sock(fd, arpp_nfqueue_receive, interfaces, NULL);

	return 0;
	
fail_create:
	arpp_printf(ARPP_DEBUG, "unbinding from queue 0\n");
	if (qh)
		nfq_destroy_queue(qh);
fail_bind:
	arpp_printf(ARPP_DEBUG, "unbinding from NFPROTO_ARP\n");
	nfq_unbind_pf(h, NFPROTO_ARP);
fail_open:
	arpp_printf(ARPP_DEBUG, "closing library handle\n");
	if (h)
		nfq_close(h);

	return -1;
	
}

void arpp_nfqueue_iface_denit(struct arpp_interfaces *interfaces)
{
	if(interfaces->qh) 
		nfq_destroy_queue(interfaces->qh);
	
	if(interfaces->h) 
		nfq_close(interfaces->h);
	
	if(interfaces->nfq_sock> -1) {
		eloop_unregister_read_sock(interfaces->nfq_sock);
		close(interfaces->nfq_sock);
		interfaces->nfq_sock = -1;
	}
}


int arpp_iface_add_if(struct arpp_interfaces *interfaces, char *ifname)
{
	struct ifreq ifr;
	int ifindex = 0;
	int ret, id;

    arpp_printf(ARPP_ERROR,"arpp_iface_add_if: interfaces=%p, ifname=%s" , interfaces, ifname);
	/*
	if (interfaces->ioctl_sock <= 0){
		interfaces->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
		arpp_printf(ARPP_ERROR,"arpp_ctrl_iface_add_if: sock=%d\n" ,interfaces->ioctl_sock);
		if (interfaces->ioctl_sock < 0) {
			perror("socket[PF_INET,SOCK_DGRAM]");
			arpp_printf(ARPP_ERROR,"socket[PF_INET,SOCK_DGRAM] errno: %s\n" , strerror(errno));
			arpp_remove_iface(interfaces, ifname);
			return -1;
		}
	}
	*/
	if (!arpp_find_iface(interfaces, ifname, &id)){
		arpp_printf(ARPP_INFO, "interface %s already added\n", ifname);
		return 0;
	}else{
		if (arpp_add_iface(interfaces, ifname)){
			arpp_printf(ARPP_ERROR, "ARPP_IFACE add failed\n");
			return -1;
		}
	}
	
	return 0;
}

int arpp_iface_del_if(struct arpp_interfaces *interfaces, char *ifname)
{
	arpp_printf(ARPP_DEBUG, "CTRL_IFACE DEL_IF %s ", ifname);
	arpp_remove_iface(interfaces, ifname);
	return 0;
}

static void arpp_database_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct arpp_interfaces *arpp_iface = eloop_ctx;
	WAM_MSG *wam_msg;
	arpp_item_t *item = NULL;
	char buf[512];
	int res, ret;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = 4096;
	int reply_len;
	unsigned int ip_addr;
	u8 *tmp;
	FILE *pf = NULL;
	char cmd[64]={0};
	
	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
			   (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}

	printPacketBuffer(buf, res);

	wam_msg = (WAM_MSG *)&buf;
	ip_addr = ntohl(wam_msg->ip_addr);
	tmp = (u8 *)&(ip_addr);
	arpp_printf(ARPP_INFO, "op = %d", wam_msg->op);
	arpp_printf(ARPP_INFO, "iface: %s\n", wam_msg->iface);
	arpp_printf(ARPP_INFO, "bridge: %s\n", wam_msg->bridge);
	arpp_printf(ARPP_INFO, "ssid: %s\n", wam_msg->ssid);
	arpp_printf(ARPP_INFO, "addr: " MACSTR "\n", MAC2STR(wam_msg->addr));
	arpp_printf(ARPP_INFO, "ip_addr: %d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);
	arpp_printf(ARPP_INFO, "lease_time : %u\n", wam_msg->lease_time);

	if (wam_msg->op == STA_ADD) {
		item = arpp_tbl_item_new_from_msg(wam_msg);
		if (item != NULL) {
			arpp_printf(ARPP_INFO, "add ip_addr: %d.%d.%d.%d\n", tmp[0], tmp[1], tmp[2], tmp[3]);
			if (arpp_tbl_item_insert(item)) {
				arpp_printf(ARPP_ERROR, "Failed to insert arpp_tbl_item!!!\n");
				return;
			}
		}else {
			arpp_printf(ARPP_ERROR, "Failed to create arpp_tbl_item!!!\n");
			return;
		}
	}
	else if (wam_msg->op == STA_DEL) {
		item = arpp_tbl_item_find_by_ip(ntohl(wam_msg->ip_addr));
		if (item != NULL) {
			arpp_tbl_item_remove(item);
			return;
		}
		
	}else if(wam_msg->op == ARPP_ENABLE){
		arpp_iface_add_if(arpp_iface, wam_msg->iface);
		if(arpp_iface->count && !golbal_arp_proxy_switch){

			golbal_arp_proxy_switch = 1;
			sprintf(cmd,"echo 1 > /sys/module/arpq_kmod/parameters/arppm_switch");
			if (NULL == (pf = popen(cmd, "r")))
    		{
        		arpp_printf(ARPP_ERROR, "%s, error: %s", __func__, strerror(errno));
    		}
    		else
    		{
        		pclose(pf);
    		}
		}
			
	}else if(wam_msg->op == ARPP_DISABLE){
		arpp_iface_del_if(arpp_iface, wam_msg->iface);
		if(!arpp_iface->count && golbal_arp_proxy_switch){

			golbal_arp_proxy_switch = 0;
			sprintf(cmd,"echo 0 > /sys/module/arpq_kmod/parameters/arppm_switch");
			if (NULL == (pf = popen(cmd, "r")))
    		{
        		arpp_printf(ARPP_ERROR, "%s, error: %s", __func__, strerror(errno));
    		}
    		else
    		{
        		pclose(pf);
    		}
		}
	}
	
	return;
}
int arpp_send_msg_to_wam(Operate op, struct arpp_interfaces *interfaces)
{
	int ret;
	struct sockaddr_un addr;
	WAM_MSG msg;
	int s = interfaces->database_iface_sock;

	os_memset(&msg, 0, sizeof(msg));
	msg.op = op;
	os_memset(&addr, 0, sizeof(addr));
#ifdef __FreeBSD__
	addr.sun_len = sizeof(addr);
#endif /* __FreeBSD__ */
	addr.sun_family = AF_UNIX;
	
	os_strlcpy(addr.sun_path, "/var/run/arpp_wam/arpp_wam", sizeof(addr.sun_path));
	ret = sendto(s, &msg, sizeof(msg), 0, (struct sockaddr *) &addr, sizeof(addr));
	if(ret < 0){
		arpp_printf(ARPP_ERROR,"send message to wam failed\n");
		return -1;
	}
	arpp_printf(ARPP_DEBUG,"send message to wam successful\n");

	return 0;
}
	
int arpp_database_iface_init(struct arpp_interfaces *interfaces)
{
	struct sockaddr_un addr;
	int s = -1;

	interfaces->database_iface_path= os_strdup(ARPP_DATABASE_IFACE_PATH);
	if (interfaces->database_iface_path == NULL) {
		arpp_printf(ARPP_DEBUG, "ctrl_iface_path not configured!\n");
		return 0;
	}

	if (mkdir(ARPP_FILE_DIR, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			arpp_printf(ARPP_DEBUG, "Using existing control "
				   "interface directory.\n");
		} else {
			perror("mkdir[ctrl_path]");
			goto fail;
		}
	}

	if (os_strlen(interfaces->database_iface_path) >= sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, interfaces->database_iface_path, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		arpp_printf(ARPP_DEBUG, "ctrl_iface bind(PF_UNIX) failed: %s\n",
			   strerror(errno));
		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			arpp_printf(ARPP_DEBUG, "ctrl_iface exists, but does not"
				   " allow connections - assuming it was left"
				   "over from forced program termination\n");
			if (unlink(interfaces->database_iface_path) < 0) {
				perror("unlink[ctrl_iface]");
				arpp_printf(ARPP_ERROR, "Could not unlink "
					   "existing ctrl_iface socket '%s'\n",
					   interfaces->database_iface_path);
				goto fail;
			}
			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
			    0) {
				perror("bind(PF_UNIX)");
				goto fail;
			}
			arpp_printf(ARPP_DEBUG, "Successfully replaced leftover "
				   "ctrl_iface socket '%s'\n", interfaces->database_iface_path);
		} else {
			arpp_printf(ARPP_INFO, "ctrl_iface exists and seems to "
				   "be in use - cannot override it\n");
			arpp_printf(ARPP_INFO, "Delete '%s' manually if it is "
				   "not used anymore\n", interfaces->database_iface_path);
			os_free(interfaces->database_iface_path);
			interfaces->database_iface_path = NULL;
			goto fail;
		}
	}

	if (chmod(interfaces->database_iface_path, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	os_free(interfaces->database_iface_path);

	interfaces->database_iface_sock = s;
	eloop_register_read_sock(s, arpp_database_iface_receive, interfaces, NULL);
	arpp_send_msg_to_wam(ARPP_CONFIG, interfaces);
	return 0;
fail:
	if (s >= 0)
		close(s);
	if (interfaces->database_iface_path) {
		unlink(interfaces->database_iface_path);
		os_free(interfaces->database_iface_path);
	}
	return -1;
}

void arpp_database_iface_deinit(struct arpp_interfaces *interfaces)
{
	char ifname[64] = ARPP_DATABASE_IFACE_PATH;

	if(interfaces->database_iface_sock > -1) {
		eloop_unregister_read_sock(interfaces->database_iface_sock);
		close(interfaces->database_iface_sock);
		interfaces->database_iface_sock = -1;
		unlink(ifname);
	}
		
}


void arpp_iface_free(struct arpp_iface *iface)
{	
	if (iface && iface->sock_arp) {
			l2_packet_deinit(iface->sock_arp);
	}

	if (iface)
		os_free(iface);
}


struct arpp_iface *arpp_iface_alloc(struct arpp_interfaces *interfaces)
{
	struct arpp_iface *arpp_if;

	if (interfaces->count == 0) {
		interfaces->iface = os_zalloc(sizeof(struct arpp_iface *));
		if (interfaces->iface == NULL) {
			arpp_printf(ARPP_ERROR, "malloc failed\n");
			return NULL;
		}
	} else {
		struct arpp_iface **iface;
		iface = os_realloc(interfaces->iface,
				   (interfaces->count + 1) *
				   sizeof(struct arpp_iface *));
		if (iface == NULL)
			return NULL;
		interfaces->iface = iface;
	}
	arpp_if = interfaces->iface[interfaces->count] =
		os_zalloc(sizeof(*arpp_if));
	if (arpp_if == NULL) {
		arpp_printf(ARPP_ERROR, "%s: Failed to allocate memory for "
			   "the interface\n", __func__);
		return NULL;
	}
	interfaces->count++;

	return arpp_if;
}


int arpp_add_iface(struct arpp_interfaces *interfaces, char *buf)
{
	struct arpp_iface *arpp_if = NULL;
	char brname[IFNAMSIZ], buffer[60], *ptr;
	size_t i, iface_count;

	os_strlcpy(brname, buf, sizeof(brname));

	for (i = 0; i < interfaces->count; i++) {
		if (!os_strcmp(interfaces->iface[i]->ifname, brname)) {
			arpp_printf(ARPP_ERROR, "BR-iface already exists!!\n");
			
			return -1;
		}
	}
	
	iface_count = i;
	if (iface_count == interfaces->count) {
		arpp_if = arpp_iface_alloc(interfaces);
		if (arpp_if == NULL) {
			arpp_printf(ARPP_ERROR, "%s: Failed to allocate memory "
				   "for interface\n", __func__);
			return -1;
		}
		os_strlcpy(arpp_if->ifname, brname, sizeof(arpp_if->ifname));
	
		return 0;
	}

	return -1;
}


int arpp_remove_iface(struct arpp_interfaces *interfaces, char *buf)
{
	struct arpp_iface *arpp_if;
	char brname[IFNAMSIZ];
	size_t i, k = 0;

	os_strlcpy(brname, buf, sizeof(brname));

	for (i = 0; i < interfaces->count; i++) {
		arpp_if = interfaces->iface[i];
		if (arpp_if == NULL)
			return -1;
		if (!os_strcmp(arpp_if->ifname, brname)) {
			arpp_iface_free(arpp_if);
			k = i;
			while (k < (interfaces->count - 1)) {
				interfaces->iface[k] =
					interfaces->iface[k + 1];
				k++;
			}
			interfaces->count--;
			return 0;
		}
	}
	arpp_printf(ARPP_ERROR, "%s: %s\n", __func__, buf);
	return 0;
}

int arpp_find_iface(struct arpp_interfaces *interfaces, char *buf, unsigned int *id)
{
	char brname[IFNAMSIZ + 1], buffer[60], *ptr;
	size_t i, iface_count;

	os_strlcpy(brname, buf, sizeof(brname));
	
	for (i = 0; i < interfaces->count; i++) {
		if (!os_strcmp(interfaces->iface[i]->ifname, brname)) {
			arpp_printf(ARPP_INFO, "BR-iface already found!!\n");
			
			*id = i;
			return 0;
		}
	}
	
	iface_count = i;
	if (iface_count == interfaces->count) {
		arpp_printf(ARPP_DEBUG, "BR-iface not found!!\n");
		
		return 1;
	}
	
	return -1;
}

/* The rtrim() function removes trailing spaces from a string. */
char *rtrim(char *str)
{
        int n = strlen(str) - 1;
	while((*(str + n) == ' ') ||(*(str + n) == '\n') ||(*(str + n) == '\r'))
	{
                *(str+n--) = '\0';
	}
}

