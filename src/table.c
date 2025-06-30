/* See LICENSE file for license details */
/* table - network analyzer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "table.h"
#include "tui.h"

static pcap_t *handle = NULL;
static volatile int running = 0;

void packet_h(u_char *user_data __attribute__((unused)), const struct pcap_pkthdr *pk,const u_char *pt){
	Information info = {0};
	struct ip *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	char timestamp[20];
	time_t n = pk->ts.tv_sec;
	struct tm *tmn = localtime(&n);

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tmn);
	snprintf(info.timestamp, sizeof(info.timestamp), "%s", timestamp);
	ip_header = (struct ip*)(pt + sizeof(struct ether_header));
	snprintf(info.source_ip, sizeof(info.source_ip), "%s", inet_ntoa(ip_header->ip_src));
	snprintf(info.dest_ip, sizeof(info.dest_ip), "%s", inet_ntoa(ip_header->ip_dst));
	switch(ip_header->ip_p){
		case IPPROTO_TCP:
			snprintf(info.protocol, sizeof(info.protocol), "tcp");
			tcp_header = (struct tcphdr*)(pt + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
			info.source_port = ntohs(tcp_header->th_sport);
			info.dest_port = ntohs(tcp_header->th_dport);
			break;
		case IPPROTO_UDP:
			snprintf(info.protocol, sizeof(info.protocol), "udp");
			udp_header = (struct udphdr*)(pt + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
			info.source_port = ntohs(udp_header->uh_sport);
			info.dest_port = ntohs(udp_header->uh_dport);
			break;
		default:
			snprintf(info.protocol, sizeof(info.protocol), "other");
			info.source_port = 0;
			info.dest_port = 0;
		}

		info.bytes = pk->len;
		size_t data_offset = sizeof(struct ether_header) + (ip_header->ip_hl * 4);
		if (ip_header->ip_p == IPPROTO_TCP){
			data_offset += (tcp_header->th_off * 4);
		} else if(ip_header->ip_p == IPPROTO_UDP){
			data_offset += sizeof(struct udphdr);
		}

		size_t data_len = pk->len - data_offset;
		if(data_len > 0){
			size_t copy_len = data_len > sizeof(info.data) - 1 ? sizeof(info.data) - 1 : data_len;
			memcpy(info.data, pt + data_offset, copy_len);
			info.data[copy_len] = '\0';
		} else {
			info.data[0] = '\0';
		}

	updt_tui(&info);
}

void start_analysis(const char *in, int tapping){
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "ip";
	if(handle != NULL){
		stop_analysis();
	}

	bpf_u_int32 net = 0;
	bpf_u_int32 mask = 0;

	handle = pcap_open_live(in, BUFSIZ, tapping, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "couldnt open %s\n", errbuf);
		return;
	}

	if(pcap_lookupnet(in, &net, &mask, errbuf) == -1){
		fprintf(stderr, "couldnt get netmask for %s: %s\n", in, errbuf);
		net = 0;
		mask = 0;
	}

	if(pcap_compile(handle, &fp, filter_exp, 0, mask) == -1){
		fprintf(stderr, "couldnt parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_close(handle);
		return;
	}

	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "couldnt get filter %s: %s\n", filter_exp, pcap_geterr(handle));
		pcap_close(handle);
		return;
	}

	running = 1;
	tui();
	while(running){
		pcap_dispatch(handle, 0, packet_h, NULL);
	}

	pcap_close(handle);
	handle = NULL;
	cl_tui();
}

void stop_analysis(){
	running = 0;
}

int is_tor_active(){
	FILE *f;
	char path[256];
	f = popen("pgrep -x tor", "r");
	if(f == NULL){
		return 0;
	}

	if(fgets(path, sizeof(path), f) != NULL){
		pclose(f);
		return 1;
	}

	pclose(f);
	return 0;
}

void help(){
	printf("table - network analyzer\n");
	printf("usage: table [options]..\n");
	printf("options:\n");
	printf("  --interface	specify network to analysis\n");
	printf("  --tapping	enable tapping mode\n");
	printf("  --version	show version information\n");
	printf("  --help	display this\n");
}

void show_version(){
	printf("%s\n", version);
}

int main(int argc, char *argv[]){
	char *in = NULL;
	int tapping = 0;
	int opts;
	int lnidx = 0;
	static struct option lnopts[] = {
		{"help", no_argument, 0, 1},
		{"version", no_argument, 0, 2},
		{"interface", required_argument, 0, 0},
		{"tapping", no_argument, 0, 0},
		{0, 0, 0, 0}
	};

	while((opts = getopt_long(argc, argv, "", lnopts, &lnidx)) != -1){
		switch(opts){
			case 0:
				if(strcmp(lnopts[lnidx].name, "interface") == 0){
					in = optarg;
				} else if(strcmp(lnopts[lnidx].name, "tapping") == 0){
					tapping = 1;
				}

				break;
			case 1:
				help();
				return 0;
			case 2:
				show_version();
				return 0;
			default:
				help();
				return 1;
		}
	}

	if(in == NULL){
		fprintf(stderr, "no interface specified, use --interface\n");
		help();
		return 1;
	}

	start_analysis(in, tapping);
	return 0;
}
