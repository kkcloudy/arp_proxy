/*
 * arp-proxy - command line interface for arp-proxy daemon
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <sys/un.h>

#include "arpp_cli.h"
#include "common.h"
#include "arp_proxy.h"


struct arpp_ctrl *ctrl_conn;
struct arpp_ctrl {
	int s;
	struct sockaddr_un local;
	struct sockaddr_un dest;
};

int arpp_ctrl_request(struct arpp_ctrl *ctrl, const char *cmd, size_t cmd_len,
		     char *reply, size_t *reply_len,
		     void (*msg_cb)(char *msg, size_t len))
{
	struct timeval tv;
	int res;
	fd_set rfds;
	const char *_cmd;
	char *cmd_buf = NULL;
	size_t _cmd_len;

	_cmd = cmd;
	_cmd_len = cmd_len;

	if (send(ctrl->s, _cmd, _cmd_len, 0) < 0) {
		os_free(cmd_buf);
		return -1;
	}
	os_free(cmd_buf);

	for (;;) {
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(ctrl->s, &rfds);
		res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
		if (res < 0)
			return res;
		if (FD_ISSET(ctrl->s, &rfds)) {
			res = recv(ctrl->s, reply, *reply_len, 0);
			if (res < 0)
				return res;
			if (res > 0 && reply[0] == '<') {
				/* This is an unsolicited message from
				 * wpa_supplicant, not the reply to the
				 * request. Use msg_cb to report this to the
				 * caller. */
				if (msg_cb) {
					/* Make sure the message is nul
					 * terminated. */
					if ((size_t) res == *reply_len)
						res = (*reply_len) - 1;
					reply[res] = '\0';
					msg_cb(reply, res);
				}
				continue;
			}
			*reply_len = res;
			break;
		} else {
			return -2;
		}
	}
	return 0;
}

static void arpp_cli_msg_cb(char *msg, size_t len)
{
	printf("%s\n", msg);
}

static int _arpp_ctrl_command(struct arpp_ctrl *ctrl, char *cmd, int print)
{
	char buf[4096];
	size_t len;
	int ret;

	if (ctrl_conn == NULL) {
		printf("Not connected to hostapd - command dropped.\n");
		return -1;
	}
	len = sizeof(buf) - 1;
	ret = arpp_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len,
			       arpp_cli_msg_cb);
	if (ret == -2) {
		printf("'%s' command timed out.\n", cmd);
		return -2;
	} else if (ret < 0) {
		printf("'%s' command failed.\n", cmd);
		return -1;
	}
	if (print) {
		buf[len] = '\0';
		printf("%s", buf);
	}
	return 0;
}


static inline int arpp_ctrl_command(struct arpp_ctrl *ctrl, char *cmd)
{
	return _arpp_ctrl_command(ctrl, cmd, 1);
}

static int hostapd_cli_cmd_show_item(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	return arpp_ctrl_command(ctrl,"SHOW_ITEM");
}

static int hostapd_cli_cmd_add_if(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid ADD_IF command: needs one argument (bridge interface "
		       "name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "ADD_IF %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long ADD_IF command.\n");
		return -1;
	}
	return arpp_ctrl_command(ctrl, cmd);
}

static int hostapd_cli_cmd_del_if(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	if (argc != 1) {
		printf("Invalid DEL_IF command: needs one argument (bridge interface "
		       "name)\n");
		return -1;
	}

	res = os_snprintf(cmd, sizeof(cmd), "DEL_IF %s", argv[0]);
	if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
		printf("Too long DEL_IF command.\n");
		return -1;
	}
	return arpp_ctrl_command(ctrl, cmd);
}

static int arpp_cli_cmd_show_if(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	return arpp_ctrl_command(ctrl,"SHOW_IF");
}

static int arpp_cli_cmd_service_switch(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;
	
	if (argc != 1) {
		printf("Invalid SERVICE command: needs one argument (enable or "
		       "disable)\n");
		return -1;
	}

	printf("argv[0] = %s\n", argv[0]);

	memset(cmd, 0, sizeof(cmd));

	if (os_strcmp(argv[0], "enable") == 0) {
		res = os_snprintf(cmd, sizeof(cmd), "SERVICE %s", argv[0]);
		if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
			printf("Too long SERVICE command.\n");
			return -1;
		}
	}
	else if (os_strcmp(argv[0], "disable") == 0) {
		res = os_snprintf(cmd, sizeof(cmd), "SERVICE %s", argv[0]);
		if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
			printf("Too long SERVICE command.\n");
			return -1;
		}
	}
	else {
		printf("Invalid SERVICE command: needs one argument (enable or "
		       "disable)\n");
		return -1;
	}

	printf("cmd = %s\n", cmd);

	return arpp_ctrl_command(ctrl, cmd);
}

static int arpp_cli_cmd_ping(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	return arpp_ctrl_command(ctrl, "PING");
}

static int arpp_cli_cmd_reload(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	return arpp_ctrl_command(ctrl, "RELOAD");
}

static int arpp_cli_cmd_log_level(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	char cmd[256];
	int res;

	memset(cmd, 0, sizeof(cmd));
	
	if(argc ==0) {
		return arpp_ctrl_command(ctrl,"LOG_LEVEL");
	}
	else if(argc == 1) {
		res = os_snprintf(cmd, sizeof(cmd), "LOG_LEVEL %s",argv[0])	;
		if (res < 0 || (size_t) res >= sizeof(cmd) - 1) {
			printf("Too long LOG_LEVEL command.\n");
			return -1;
		}
		return arpp_ctrl_command(ctrl, cmd);
	}
	else {
		printf("Invalid LOG_LEVEL command: argument error.\n!");
		return -1;
	}
}


struct arpp_cli_cmd {
	const char *cmd;
	int (*handler)(struct arpp_ctrl *ctrl, int argc, char *argv[]);
};

static struct arpp_cli_cmd arpp_cli_commands[] = {
	{ "service", arpp_cli_cmd_service_switch },
	{ "show_if", arpp_cli_cmd_show_if },
	{ "show_item", hostapd_cli_cmd_show_item },
	{ "log_level",arpp_cli_cmd_log_level},
	{ NULL, NULL }
};

static void arpp_cli_request(struct arpp_ctrl *ctrl, int argc, char *argv[])
{
	struct arpp_cli_cmd *cmd, *match = NULL;
	int count;

	count = 0;
	cmd = arpp_cli_commands;
	while (cmd->cmd) {
		if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) == 0) {
			match = cmd;
			if (os_strcasecmp(cmd->cmd, argv[0]) == 0) {
				/* we have an exact match */
				count = 1;
				break;
			}
			count++;
		}
		cmd++;
	}

	if (count > 1) {
		printf("Ambiguous command '%s'; possible commands:", argv[0]);
		cmd = arpp_cli_commands;
		while (cmd->cmd) {
			if (strncasecmp(cmd->cmd, argv[0], strlen(argv[0])) ==
			    0) {
				printf(" %s", cmd->cmd);
			}
			cmd++;
		}
		printf("\n");
	} else if (count == 0) {
		printf("Unknown command '%s'\n", argv[0]);
	} else {
		match->handler(ctrl, argc - 1, &argv[1]);
	}
}

struct arpp_ctrl *arpp_cli_open_connection(void)
{
	struct arpp_ctrl *ctrl;
	static int counter = 0;
	int ret;
	size_t res;
	int tries = 0;

	ctrl = os_malloc(sizeof(*ctrl));
	if (ctrl == NULL)
		return NULL;
	os_memset(ctrl, 0, sizeof(*ctrl));

	ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (ctrl->s < 0) {
		os_free(ctrl);
		return NULL;
	}

	ctrl->local.sun_family = AF_UNIX;
	counter++;
try_again:
	ret = os_snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
			  ARPP_CLI_PATH "%d-%d",(int) getpid(), counter);
	if (ret < 0 || (size_t) ret >= sizeof(ctrl->local.sun_path)) {
		close(ctrl->s);
		os_free(ctrl);
		return NULL;
	}
	
	tries++;
	if (bind(ctrl->s, (struct sockaddr *) &ctrl->local,
			sizeof(ctrl->local)) < 0) {
		if (errno == EADDRINUSE && tries < 2) {
			/*
			 * getpid() returns unique identifier for this instance
			 * of wpa_ctrl, so the existing socket file must have
			 * been left by unclean termination of an earlier run.
			 * Remove the file and try again.
			 */
			unlink(ctrl->local.sun_path);
			goto try_again;
		}
		close(ctrl->s);
		os_free(ctrl);
		return NULL;
	}

	ctrl->dest.sun_family = AF_UNIX;
	res = strlcpy(ctrl->dest.sun_path, ARPP_CTRL_IFACE_PATH,
			 sizeof(ctrl->dest.sun_path));
	if (res >= sizeof(ctrl->dest.sun_path)) {
		close(ctrl->s);
		os_free(ctrl);
		return NULL;
	}
	if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest,
		    sizeof(ctrl->dest)) < 0) {
		close(ctrl->s);
		unlink(ctrl->local.sun_path);
		os_free(ctrl);
		return NULL;
	}

	return ctrl;
}

void arpp_cli_close_connection(struct arpp_ctrl *ctrl)
{
	if (ctrl == NULL)
		return;
	unlink(ctrl->local.sun_path);
	if (ctrl->s >= 0)
		close(ctrl->s);
	os_free(ctrl);
}


int main(int argc, char *argv[])
{
	int i;

	printf("argc: %d\n", argc);
	for (i = 0; i < argc; i++) {
		printf("argv[%d]: %s\n", i, argv[i]);
	}

	ctrl_conn = arpp_cli_open_connection();

	arpp_cli_request(ctrl_conn, argc - 1, &argv[1]);

	arpp_cli_close_connection(ctrl_conn);

	return 0;
}

