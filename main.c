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

pkthdr change_endian_header(pkthdr header) {
	char* big_endian = (char*)&header;
	char little_endian[24];
	memset(little_endian, 0, sizeof(char)*24);

	little_endian[0] = big_endian[0];
	little_endian[1] = big_endian[1];
	little_endian[2] = big_endian[2];
	little_endian[3] = big_endian[3];
	// timeval sec(big_endian)

	little_endian[12] = big_endian[7];
	little_endian[13] = big_endian[6];
	little_endian[14] = big_endian[5];
	little_endian[15] = big_endian[4];
	// timeval usec(little_endian)

	little_endian[16] = big_endian[11];
	little_endian[17] = big_endian[10];
	little_endian[18] = big_endian[9];
	little_endian[19] = big_endian[8];
	// caplen

	little_endian[20] = big_endian[15];
	little_endian[21] = big_endian[14];
	little_endian[22] = big_endian[13];
	little_endian[23] = big_endian[12];
	// len

	return *( (pkthdr*) little_endian );
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
	readfile((char*)&header, fp, 16);
	printhexa((unsigned char*)&header, 16);
	header = change_endian_header(header);
	printhexa((unsigned char*)&header, 24);

	struct tm* time;
	time = localtime(&header.time.tv_sec);
	if(time == NULL){
		printf("Time conversion Error!\n");
		exit(-1);
	}
	printtime(time);
	int a = 96;
	printhexa((unsigned char*)&a,4);

	printf("%ld %d %d",header.time.tv_usec,header.caplen,header.len);

	puts("");
	return 0;
}
