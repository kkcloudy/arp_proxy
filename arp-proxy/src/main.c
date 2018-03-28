/*
 * arp-proxy / main()
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
#include "arp_snoop.h"


/**
 * handle_term - SIGINT and SIGTERM handler to terminate hostapd process
 */
 int golbal_arp_proxy_switch = 0;
extern int arpp_debug_level;
static void handle_term(int sig, void *signal_ctx)
{
	arpp_printf(ARPP_DEBUG, "Signal %d received - terminating\n", sig);
	eloop_terminate();
}


static void arpp_ctrl_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct arpp_interfaces *arpp_iface = eloop_ctx;
	char buf[512];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply;
	const int reply_size = 4096;
	int reply_len;
	char *pos;
	FILE *pf = NULL;
	char cmd[64]={0};

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
			   (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}
	buf[res] = '\0';

	reply = os_malloc(reply_size);
	if (reply == NULL) {
		sendto(sock, "malloc FAIL\n", 5, 0, (struct sockaddr *) &from,
			   fromlen);
		return;
	}

	os_memcpy(reply, "OK\n", 3);
	reply_len = 3;

	
	if (os_strncmp(buf,"SHOW_ITEM", 9) == 0) {
		if (arpp_tbl_item_debug_show())
			reply_len = -1;
	}
	else if(os_strncmp(buf,"SHOW_IF", 7) == 0) {
		arpp_tbl_iface_debug_show(arpp_iface);
	}
	else if (os_strncmp(buf,"SERVICE ", 8) == 0) {
		arpp_printf(ARPP_DEBUG,"strlen(buf) = %d buf = %s\n",(int)strlen(buf) ,buf);
		if (os_strncmp(buf+8, "disable", 7)== 0){
			if( golbal_arp_proxy_switch == 1 ){

				golbal_arp_proxy_switch = 0;
				sprintf(cmd,"echo 0 > /sys/module/arpq_kmod/parameters/arppm_switch");
				if (NULL == (pf = popen(cmd, "r")))
    			{
        		arpp_printf(ARPP_DEBUG, "%s, error: %s", __func__, strerror(errno));
    			}
    			else
    			{
        			pclose(pf);
    			}
        		arpp_printf(ARPP_DEBUG,"golbal_arp_proxy_switch = %d\n",golbal_arp_proxy_switch);
			}
			else
				arpp_printf(ARPP_DEBUG,"switch already is disable\n");


		}
		else{
			if( golbal_arp_proxy_switch == 0 ){
				golbal_arp_proxy_switch = 1;
				sprintf(cmd,"echo 1 > /sys/module/arpq_kmod/parameters/arppm_switch");

				if (NULL == (pf = popen(cmd, "r")))
    			{
        		arpp_printf(ARPP_DEBUG, "%s, error: %s", __func__, strerror(errno));
    			}
    			else
    			{
        			pclose(pf);
    			}
				arpp_printf(ARPP_DEBUG, "golbal_arp_proxy_switch = %d\n",golbal_arp_proxy_switch);

			}
			else
				arpp_printf(ARPP_DEBUG,"switch already is enable\n");
		}
	}
	else if(os_memcmp(buf, "LOG_LEVEL", 9) == 0) {
		pos = buf+9;
		if(*pos == '\0') {
			sprintf(reply,"Current Level:%s\n",debug_level_str(arpp_debug_level));
			reply_len = os_strlen(reply);
		} 
		else if(*pos == ' ') {
			pos = buf + 10;
			int level = str_to_debug_level(pos);
			if (level < 0)
				reply_len = -1;
			arpp_debug_level = level;
		}
	}
	else {
		os_memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		os_memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}
	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	os_free(reply);
}


int arpp_global_ctrl_iface_init(struct arpp_interfaces *interfaces)
{
	struct sockaddr_un addr;
	int s = -1;

	interfaces->ctrl_iface_path = os_strdup(ARPP_CTRL_IFACE_PATH);
	if (interfaces->ctrl_iface_path == NULL) {
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

	if (os_strlen(interfaces->ctrl_iface_path) >= sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	os_strlcpy(addr.sun_path, interfaces->ctrl_iface_path, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		arpp_printf(ARPP_DEBUG, "ctrl_iface bind(PF_UNIX) failed: %s\n",
			   strerror(errno));
		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			arpp_printf(ARPP_DEBUG, "ctrl_iface exists, but does not"
				   " allow connections - assuming it was left"
				   "over from forced program termination\n");
			if (unlink(interfaces->ctrl_iface_path) < 0) {
				perror("unlink[ctrl_iface]");
				arpp_printf(ARPP_ERROR, "Could not unlink "
					   "existing ctrl_iface socket '%s'\n",
					   interfaces->ctrl_iface_path);
				goto fail;
			}
			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
			    0) {
				perror("bind(PF_UNIX)");
				goto fail;
			}
			arpp_printf(ARPP_DEBUG, "Successfully replaced leftover "
				   "ctrl_iface socket '%s'\n", interfaces->ctrl_iface_path);
		} else {
			arpp_printf(ARPP_INFO, "ctrl_iface exists and seems to "
				   "be in use - cannot override it\n");
			arpp_printf(ARPP_INFO, "Delete '%s' manually if it is "
				   "not used anymore\n", interfaces->ctrl_iface_path);
			os_free(interfaces->ctrl_iface_path);
			interfaces->ctrl_iface_path = NULL;
			goto fail;
		}
	}

	if (chmod(interfaces->ctrl_iface_path, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	os_free(interfaces->ctrl_iface_path);

	interfaces->ctrl_iface_sock = s;
	eloop_register_read_sock(s, arpp_ctrl_iface_receive, interfaces, NULL);

	return 0;
fail:
	if (s >= 0)
		close(s);
	if (interfaces->ctrl_iface_path) {
		unlink(interfaces->ctrl_iface_path);
		os_free(interfaces->ctrl_iface_path);
	}
		return -1;
}

void arpp_global_ctrl_iface_deinit(struct arpp_interfaces *interfaces)
{
	char ifname[64] = ARPP_CTRL_IFACE_PATH;

	if(interfaces->ctrl_iface_sock > -1) {
		eloop_unregister_read_sock(interfaces->ctrl_iface_sock);
		close(interfaces->ctrl_iface_sock);
		interfaces->ctrl_iface_sock = -1;
		unlink(ifname);
	}
		
}


int arpp_global_init(struct arpp_interfaces *interfaces)
{
	if (eloop_init()) {
		arpp_printf(ARPP_ERROR, "Failed to initialize event loop\n");
		return -1;
	}
	eloop_register_signal_terminate(handle_term, interfaces);
	
	if (arpp_global_ctrl_iface_init(interfaces)){
		arpp_printf(ARPP_ERROR, "Failed to setup control interface\n");
		return -1;
	}

	if (l2_arp_snoop_init(interfaces)) {
		arpp_printf(ARPP_ERROR, "Failed to setup control interface: l2_arp_snoop_init\n");
		return -1;
	}
	arpp_printf(ARPP_ERROR, "succeed to setup control interface: l2_arp_snoop_init\n");
	
	if (arpp_database_iface_init(interfaces)){
		arpp_printf(ARPP_ERROR, "Failed to setup database interface\n");
		return -1;
	}

	if (arpp_nfqueue_iface_init(interfaces)){
		arpp_printf(ARPP_ERROR, "Failed to setup database interface\n");
		return -1;
	}

	return 0;
}

static int arpp_global_run(struct arpp_interfaces *ifaces, int daemonize,
			      const char *pid_file)
{
	/*
	if (daemonize && os_daemonize(pid_file)) {
		perror("daemon");
		return -1;
	}
	*/

	eloop_run();

	return 0;
}


int main(int argc, char *argv[])
{
	struct arpp_interfaces interfaces;
	int ret = 0, daemonize = 1;
	char *pid_file = NULL;

	arp_interfaces = &interfaces;
	interfaces.count = 0;
	interfaces.ctrl_iface_path = NULL;
	interfaces.ctrl_iface_sock = 0;
	interfaces.database_iface_path = NULL;
	interfaces.database_iface_sock = 0;
	interfaces.ioctl_sock = 0;
	interfaces.nfq_sock = 0;
	interfaces.h = NULL;
	interfaces.qh = NULL;
	interfaces.l2 = NULL;
	
	ret = arpp_debug_open_file(ARPP_OUT_FILE);

	if (arpp_global_init(&interfaces)){
		arpp_printf(ARPP_DEBUG, "arpp global init failed.\n");
		goto out;
	}

	memset(arpp_item_hash_table, 0, ARPP_ITEM_HASH_TABLE_SIZE * sizeof(arpp_item_t *));
	
	pid_file = os_strdup(ARPP_PID_FILE);
	if (arpp_global_run(&interfaces, daemonize, pid_file))
		goto out;

out:
		arpp_global_ctrl_iface_deinit(&interfaces);
		l2_arp_snoop_deinit(&interfaces);
		arpp_database_iface_deinit(&interfaces);
		arpp_nfqueue_iface_denit(&interfaces);
	return 0;
}
