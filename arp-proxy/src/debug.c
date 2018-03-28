/*
 * debug/ARP Proxy / Debug prints
 * Copyright (c) 2016-2017, Cao Jia
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "debug.h"
#include "arp_proxy.h"
#include <syslog.h>

#define MAX_LOG_SIZE 65535
static int arpp_debug_syslog = 0;

int arpp_debug_level = ARPP_INFO;
int arpp_debug_show_keys = 0;
int arpp_debug_timestamp = 0;
int arpp_debug_log_size = 0;

static FILE *out_file = NULL;

void arpp_debug_print_timestamp(void)
{
	struct os_time tv;

	if (!arpp_debug_timestamp)
		return;

	os_get_time(&tv);
	if (out_file) {
		fprintf(out_file, "%ld.%06u: ", (long) tv.sec,
			(unsigned int) tv.usec);
	} else
		printf("%ld.%06u: ", (long) tv.sec, (unsigned int) tv.usec);
}

#ifndef LOG_ARPP
#define LOG_ARPP LOG_DAEMON
#endif /* LOG_ARPP */

void arpp_debug_open_syslog(void)
{
	openlog("arp-proxy", LOG_PID | LOG_NDELAY, LOG_ARPP);
	arpp_debug_syslog++;
}


void arpp_debug_close_syslog(void)
{
	if (arpp_debug_syslog)
		closelog();
}


static int syslog_priority(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
	case MSG_DEBUG:
		return LOG_DEBUG;
	case MSG_INFO:
		return LOG_NOTICE;
	case MSG_WARNING:
		return LOG_WARNING;
	case MSG_ERROR:
		return LOG_ERR;
	}
	return LOG_INFO;
}

const char * debug_level_str(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
		return "MSGDUMP";
	case MSG_DEBUG:
		return "DEBUG";
	case MSG_INFO:
		return "INFO";
	case MSG_WARNING:
		return "WARNING";
	case MSG_ERROR:
		return "ERROR";
	default:
		return "?";
	}
}


int str_to_debug_level(const char *s)
{
	if (os_strcasecmp(s, "MSGDUMP") == 0)
		return MSG_MSGDUMP;
	if (os_strcasecmp(s, "DEBUG") == 0)
		return MSG_DEBUG;
	if (os_strcasecmp(s, "INFO") == 0)
		return MSG_INFO;
	if (os_strcasecmp(s, "WARNING") == 0)
		return MSG_WARNING;
	if (os_strcasecmp(s, "ERROR") == 0)
		return MSG_ERROR;
	return -1;
}


/**
 * arpp_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */
void arpp_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	
	if(arpp_debug_log_size > MAX_LOG_SIZE) {
		arpp_debug_log_size = 0;
		arpp_debug_reopen_file();
	}
	
	if (level >= arpp_debug_level) {
		if (arpp_debug_syslog) {
			vsyslog(syslog_priority(level), fmt, ap);
		} else {
			arpp_debug_print_timestamp();
			if (out_file) {
				arpp_debug_log_size += vfprintf(out_file, fmt, ap);
				fflush(out_file);
				/*
				fprintf(out_file, "\n");
				*/
			} else {
				arpp_debug_open_file(ARPP_OUT_FILE);
			}
		}
	}
	va_end(ap);
}


static void _arpp_hexdump(int level, const char *title, const u8 *buf,
			 size_t len, int show)
{
	size_t i;

	if (level < arpp_debug_level)
		return;

	if (arpp_debug_syslog) {
		const char *display;
		char *strbuf = NULL;

		if (buf == NULL) {
			display = " [NULL]";
		} else if (len == 0) {
			display = "";
		} else if (show && len) {
			strbuf = os_malloc(1 + 3 * len);
			if (strbuf == NULL) {
				arpp_printf(MSG_ERROR, "arpp_hexdump: Failed to "
					   "allocate message buffer");
				return;
			}

			for (i = 0; i < len; i++)
				os_snprintf(&strbuf[i * 3], 4, " %02x",
					    buf[i]);

			display = strbuf;
		} else {
			display = " [REMOVED]";
		}

		syslog(syslog_priority(level), "%s - hexdump(len=%lu):%s",
		       title, (unsigned long) len, display);
		os_free(strbuf);
		return;
	}

	arpp_debug_print_timestamp();

	if (out_file) {
		fprintf(out_file, "%s - hexdump(len=%lu):",
			title, (unsigned long) len);
		if (buf == NULL) {
			fprintf(out_file, " [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				fprintf(out_file, " %02x", buf[i]);
		} else {
			fprintf(out_file, " [REMOVED]");
		}
		fprintf(out_file, "\n");
	} else {
		printf("%s - hexdump(len=%lu):", title, (unsigned long) len);
		if (buf == NULL) {
			printf(" [NULL]");
		} else if (show) {
			for (i = 0; i < len; i++)
				printf(" %02x", buf[i]);
		} else {
			printf(" [REMOVED]");
		}
		printf("\n");
	}
}

void arpp_hexdump(int level, const char *title, const u8 *buf, size_t len)
{
	_arpp_hexdump(level, title, buf, len, 1);
}


void arpp_hexdump_key(int level, const char *title, const u8 *buf, size_t len)
{
	_arpp_hexdump(level, title, buf, len, arpp_debug_show_keys);
}


static void _arpp_hexdump_ascii(int level, const char *title, const u8 *buf,
			       size_t len, int show)
{
	size_t i, llen;
	const u8 *pos = buf;
	const size_t line_len = 16;

	if (level < arpp_debug_level)
		return;

	arpp_debug_print_timestamp();
	if (out_file) {
		if (!show) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [REMOVED]\n",
				title, (unsigned long) len);
			return;
		}
		if (buf == NULL) {
			fprintf(out_file,
				"%s - hexdump_ascii(len=%lu): [NULL]\n",
				title, (unsigned long) len);
			return;
		}
		fprintf(out_file, "%s - hexdump_ascii(len=%lu):\n",
			title, (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			fprintf(out_file, "    ");
			for (i = 0; i < llen; i++)
				fprintf(out_file, " %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				fprintf(out_file, "   ");
			fprintf(out_file, "   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					fprintf(out_file, "%c", pos[i]);
				else
					fprintf(out_file, "_");
			}
			for (i = llen; i < line_len; i++)
				fprintf(out_file, " ");
			fprintf(out_file, "\n");
			pos += llen;
			len -= llen;
		}
	} else {
		if (!show) {
			printf("%s - hexdump_ascii(len=%lu): [REMOVED]\n",
				title, (unsigned long) len);
			return;
		}
		if (buf == NULL) {
			printf("%s - hexdump_ascii(len=%lu): [NULL]\n",
				title, (unsigned long) len);
			return;
		}
		printf("%s - hexdump_ascii(len=%lu):\n", title, (unsigned long) len);
		while (len) {
			llen = len > line_len ? line_len : len;
			printf("    ");
			for (i = 0; i < llen; i++)
				printf(" %02x", pos[i]);
			for (i = llen; i < line_len; i++)
				printf("   ");
			printf("   ");
			for (i = 0; i < llen; i++) {
				if (isprint(pos[i]))
					printf("%c", pos[i]);
				else
					printf("_");
			}
			for (i = llen; i < line_len; i++)
				printf(" ");
			printf("\n");
			pos += llen;
			len -= llen;
		}
	}
}


void arpp_hexdump_ascii(int level, const char *title, const u8 *buf, size_t len)
{
	_arpp_hexdump_ascii(level, title, buf, len, 1);
}


void arpp_hexdump_ascii_key(int level, const char *title, const u8 *buf,
			   size_t len)
{
	_arpp_hexdump_ascii(level, title, buf, len, arpp_debug_show_keys);
}

static char *last_path = NULL;

int arpp_debug_reopen_file(void)
{
	int rv;
	if (last_path) {
		char *tmp = os_strdup(last_path);
		arpp_debug_close_file();
		rv = arpp_debug_open_file(tmp);
		os_free(tmp);
	} else {
		arpp_printf(MSG_ERROR, "Last-path was not set, cannot "
			   "re-open log file.");
		rv = -1;
	}
	return rv;
}


int arpp_debug_open_file(const char *path)
{
	if (!path)
		return 0;

	if (last_path == NULL || os_strcmp(last_path, path) != 0) {
		/* Save our path to enable re-open */
		os_free(last_path);
		last_path = os_strdup(path);
	}

	out_file = fopen(path, "w");
	if (out_file == NULL) {
		arpp_printf(ARPP_ERROR, "arpp_debug_open_file: Failed to open "
			   "output file, using standard output");
		return -1;
	}

	return 0;
}


void arpp_debug_close_file(void)
{
	if (!out_file)
		return;
	fclose(out_file);
	out_file = NULL;
	os_free(last_path);
	last_path = NULL;
}
