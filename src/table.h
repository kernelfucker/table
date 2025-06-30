#ifndef table_h
#define table_h

/* test */

#define version "0.2"

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
void help();
void show_version();

#endif
