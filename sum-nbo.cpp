#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>

int main(int argc, char* argv[]){

    int sum = 0;
    uint32_t sum32= 0;

    for(int i=1; i<argc; i++){
        FILE *fp = fopen(argv[i], "r");
        if(fp == NULL) {
            printf("no file\n");
            return 0;
        }

        uint32_t network_num = 0x00000000;


        uint8_t ch;
        for(int i=0;i<4;i++){
            ch=fgetc(fp);
            network_num |= ch << i*8;
            //printf("%02X ",ch); //debug
        }
        //printf("\n"); //debug
        //printf("0x%08x",network_num); //debug


        //printf("------\n");


        // fread(&network_num, 1, 32, fp); //fail 1
        // //fscanf(fp, "%u", &network_num); //fail 2

        uint32_t host_num = ntohl(network_num);
        //uint32_t sum32 = sum32 + host_num;
        sum += int(host_num);


        printf("%d(0x%08x)", host_num ,host_num);

        if(i!=argc-1) printf(" + ");
        else {
            printf("= %d(0x%08x)",sum,sum);
        }

        fclose(fp);


    }

}
