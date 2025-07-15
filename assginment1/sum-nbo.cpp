#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

int main(int argc, char* argv[]){

    int sum = 0;

    for(int i=1; i<argc; i++){
        FILE *fp = fopen(argv[i], "rb");
        if(fp == NULL) {
            printf("no file\n");
            return 0;
        }


        uint32_t network_num;
	size_t ret = fread(&network_num, sizeof(uint32_t) ,1,fp);

	if (ret <= 0){
		printf("fail\n");
		return 0;
	}
 

        uint32_t host_num = ntohl(network_num);
        sum += int(host_num);


        printf("%d(0x%08x)", host_num ,host_num);

        if(i!=argc-1) printf(" + ");
        else {
            printf("= %d(0x%08x)",sum,sum);
        } 

        fclose(fp);


    }

}
