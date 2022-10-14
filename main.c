#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

typedef struct pkthdr{
	struct timeval time;
	unsigned int caplen;
	unsigned int len;
} pkthdr;

typedef struct ethhdr{
	unsigned char dest_addr[6];
	unsigned char src_addr[6];
	unsigned short length;
} ethhdr;

typedef struct iphdr{
	unsigned char header_length;	// *= 4
	unsigned char TOS;
	unsigned short total_length;
	unsigned short identification;
	unsigned short fragment_offset;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned char src_addr[4];
	unsigned char dest_addr[4];
} iphdr;

void readfile(char* buf, FILE* fp, int size) {
	int res = fread(buf, sizeof(char), size, fp);
	if(res == 0){
		printf("EOF!\n");
		exit(0);
	}
	if(res ^ size){
		printf("Buffer read Error!\n");
		exit(-1);
	}
}

pkthdr change_header(pkthdr header){
	pkthdr result;

	result.time.tv_sec = *(int*)&header;
	result.time.tv_usec = *((int*)&header + 1);
	result.caplen = *((int*)&header + 2);
	result.len = *((int*)&header + 3);

	return result;
}

void printtime(struct timeval pkttime){
	struct tm* time;
	time = localtime(&pkttime.tv_sec);
	if(time == NULL){
		printf("Time conversion Error!\n");
		exit(-1);
	}
	printf("  %02d:%02d:%02d.%06ld  ", time->tm_hour, time->tm_min, time->tm_sec, pkttime.tv_usec);
}

void print_MAC_addr(ethhdr eth_header){
	printf("  ");
	for(int i = 0; i < 6; i++){
		printf("%.2x",eth_header.src_addr[i]);
		if(i != 5)
			printf(":");
	}
	printf(" -> ");
	for(int i = 0; i < 6; i++){
		printf("%.2x",eth_header.dest_addr[i]);
		if(i != 5)
			printf(":");
	}
	printf(" ");
}

void change_endian_iphdr(iphdr* input){
	unsigned char swp = ((unsigned char*)input)[3];
	((unsigned char*)input)[3] = ((unsigned char*)input)[2];
	((unsigned char*)input)[2] = swp;
	// total_length changed
	swp = ((unsigned char*)input)[5];
	((unsigned char*)input)[5] = ((unsigned char*)input)[4];
	((unsigned char*)input)[4] = swp;
	// identification changed
	swp = ((unsigned char*)input)[7];
	((unsigned char*)input)[7] = ((unsigned char*)input)[6];
	((unsigned char*)input)[6] = swp;
	// fragment_offset changed

	// need to change header_checksum
}

void print_ip_addr(iphdr ip_header){
	char str1[20];
	sprintf( str1, "%u.%u.%u.%u", ip_header.src_addr[0], ip_header.src_addr[1], ip_header.src_addr[2], ip_header.src_addr[3]);

	char str2[20];
	sprintf( str2, "%u.%u.%u.%u", ip_header.dest_addr[0], ip_header.dest_addr[1], ip_header.dest_addr[2], ip_header.dest_addr[3]);
	printf("  %-16s%2s%17s", str1, "->", str2);
	printf("    ");
}
	
void print_ip_protocol(unsigned char protocol){
	switch(protocol){
		case 1:
			printf("%8s", "ICMP  ");
			break;
		case 2:
			printf("%8s", "IGMP  ");
			break;
		case 6:
			printf("%8s", "TCP  ");
			break;
		case 9:
			printf("%8s", "IGRP  ");
			break;
		case 17:
			printf("%8s", "UDP  ");
			break;
		case 47:
			printf("%8s", "GRE  ");
			break;
		case 50:
			printf("%8s", "ESP  ");
			break;
		case 51:
			printf("%8s", "AH   ");
			break;
		case 57:
			printf("%8s", "SKIP  ");
			break;
		case 88:
			printf("%8s", "EIGRP ");
			break;
		case 89:
			printf("%8s", "OSPF  ");
			break;
		case 115:
			printf("%8s", "L2TP  ");
			break;
		default:
			printf("%8s", "ETC  ");
	}
}

void print_ip_flags(unsigned short identification){
	printf("%9u%6u", (identification & (1 << 14)) >> 14, (identification & (1 << 13)) >> 13);
}
	
// for debug
void printhexa(unsigned char* buf, int size) {
	printf("///////////////  print  ///////////////\n");
	for(int i = 0; i < size; i++){
		if(i % 2 == 0 && i)
			printf(" ");
		if(i % 16 == 0 && i)
			printf("\n");
		printf("%.2x", buf[i]);
	}
	printf("\n//////////////    fin   ///////////////\n");
}

int main(){
	// file open
	FILE* fp;
	fp = fopen("CN_Packets.pcap","rb");
	if(!fp){
		printf("File open failed!\n");
		return 0;
	}
	char buffer[30000];		// 정해진 size만큼 읽기 위한 buffer
	
	readfile(buffer, fp, 24);
	// Read file information
	
	int packet_no = 0;
	printf("%5s%20s%20s%21s%18s%20s%12s%16s%6s%6s%7s%7s%17s%17s%24s\n", "No. ", "Time        ", "Source MAC     ", "Destination MAC   ","Souce IP     ", "Destination IP  ", "protocol  ", "Identification ", "DF  ", "MF  ", "TTL  ", "ToS  ", "captured length ", "actual length  ", "length in the IP header");
	while(1){
		packet_no++;
		pkthdr pkt_header;
		readfile((char*)&pkt_header, fp, 16);
		printf("%5d",packet_no);
		pkt_header = change_header(pkt_header);
		
		printtime(pkt_header.time);
		//printf("%ld %d %d",header.time.tv_usec,header.caplen,header.len);
		// Read pcap_pkthdr
	
		ethhdr eth_header;
		readfile((char*)&eth_header, fp, 14);
		char arpflag = 1;
		char checknum = 0;
		checknum -= 1;
		for(int i = 0; i < 6; i++){
			char* tmp = (char*)&eth_header;
			if(tmp[i] ^ checknum)
				arpflag = 0;
		}

		print_MAC_addr(eth_header);
		// Read ethernet header
		if(arpflag){
			readfile(buffer, fp, pkt_header.len - 14);
			puts("");
			continue;
		}
	
		iphdr ip_header;
		readfile((char*)&ip_header, fp, 20);
		unsigned char ip_ver = ((unsigned char*)&ip_header)[0];
		int isipv6 = 0;
		if( (ip_ver & 0B11110000) == 0B01100000){
			isipv6 = 1;
		}
		ip_header.header_length &= 15; // 0000 1111
		change_endian_iphdr(&ip_header);
		if(ip_header.header_length > 5)
			readfile(buffer, fp, (ip_header.header_length - 5) * 4);	// Read ip_header option
		
		if(isipv6)
			printf("  //////////  IPv6  //////////  IPv6  //////////  IPv6  //////////  IPv6  //////////  IPv6  //////////  IPv6  //////////  IPv6  //////////\n");
		else{
			print_ip_addr(ip_header);
			print_ip_protocol(ip_header.protocol);
			printf("%8s%-5hu", "", ip_header.identification);
			print_ip_flags(ip_header.fragment_offset);
			printf("    %3u", ip_header.TTL);
			printf("    %3u", ip_header.TOS);
			printf("%12u%5s%12u%5s%15u\n", pkt_header.caplen, "", pkt_header.len, "", ip_header.total_length);
		}

		if(isipv6)
			readfile(buffer, fp, pkt_header.len - 34);
		else
			readfile(buffer, fp, pkt_header.len - ip_header.header_length * 4 - 14);	// actual length - ip_header length - ethernet header length
		if(packet_no == 15685)
			return 0;
	}
	puts("");
	return 0;
}
