#ifndef table_h
#define table_h

#define version "0.5"

typedef struct{
	char source_ip[16];
	char dest_ip[16];
	unsigned short source_port;
	unsigned short dest_port;
	char protocol[8];
	unsigned int bytes;
	char timestamp[20];
	char data[256];
} Information;

void start_analysis(const char *in, int tapping);
void stop_analysis();
int is_tor_active();
int is_sshd_active();
int is_ftpd_active();

void help();
void show_version();

#endif
