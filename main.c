#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

typedef struct pkthdr{
	struct timeval time;
	int caplen;
	int len;
} pkthdr;

void readfile(char* buf, FILE* fp, int size) {
	int res = fread(buf, sizeof(char), size, fp);
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

void printtime(struct tm* tm){
    printf("지금시간: %04d-%02d-%02d %02d:%02d:%02d\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
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
	printf("%d %d",sizeof(struct timeval),sizeof(int));

	char buffer[10000];		// 정해진 size만큼 읽기 위한 buffer

	readfile(buffer, fp, 24);
	//printhexa((unsigned char*)buffer, 24);
	// Read file information

	pkthdr header;
	//readfile((char*)&header, fp, 16);
	//printhexa((unsigned char*)&header, 16);
	header = change_header(header);
	//printhexa((unsigned char*)&header, 24);

	struct tm* time;
	time = localtime(&header.time.tv_sec);
	if(time == NULL){
		printf("Time conversion Error!\n");
		exit(-1);
	}
	//printtime(time);
	//printf("%ld %d %d",header.time.tv_usec,header.caplen,header.len);


	puts("");
	return 0;
}
