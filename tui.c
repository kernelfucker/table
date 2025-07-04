#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include "tui.h"

#define max_items 30

static Information packet[max_items];
static int pt_index = 0;
static int tor_active = 0;
static int sshd_active = 0;
static int ftpd_active = 0;

void clear(){
	printf("\033[2J\033[H");
}

void tui(){
	clear();
	tor_active = is_tor_active();
	sshd_active = is_sshd_active();
	ftpd_active = is_ftpd_active();
}

void cl_tui(){
	clear();
}

void updt_tui(Information *info){
	memcpy(&packet[pt_index], info, sizeof(Information));
	pt_index = (pt_index + 1) % max_items;
	draw_tui();
}

void draw_tui(){
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	printf("\033[H\033[J");
	printf("table: %s | tor: %s | sshd: %s | ftpd: %s\n",
		version,
		tor_active ? "active" : "inactive",
		sshd_active ? "active" : "inactive",
		ftpd_active ? "active" : "inactive");

	printf("\n");
	for(int i = 0; i < w.ws_col; i++) printf("-");
	printf("\n");
	printf("%-19s %-15s %-6s %-15s %-6s %-8s %-8s %-20s\n",
		"timestamp", "source ip", "port", "dest ip", "port", "protocol", "bytes", "data");

	for(int i = 0; i < w.ws_col; i++) printf("-");
	printf("\n");
	for(int i = 0; i < max_items; i++){
		int id = (pt_index + i) % max_items;
		if(packet[id].timestamp[0] == '\0') continue;
		printf("%-19s %-15s %-6d %-15s %-6d %-8s %-8d ",
			packet[id].timestamp,
			packet[id].source_ip,
			packet[id].source_port,
			packet[id].dest_ip,
			packet[id].dest_port,
			packet[id].protocol,
			packet[id].bytes);

		for(int j = 0; j < 20 && packet[id].data[j] != '\0'; j++){
			if(packet[id].data[j] >= 32 && packet[id].data[j] <= 126){
				putchar(packet[id].data[j]);
			} else {
				putchar('.');
			}
		}

		printf("\n");
	}

	for(int i = 0; i < w.ws_col; i++) printf("-");
	printf("\n");
	printf("press control-c to stop analyzing\n");
	fflush(stdout);
}
