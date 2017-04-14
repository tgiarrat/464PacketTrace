#include <pcap.h>
#include <stdint.h>
#include "trace.h"
#include <net/ethernet.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {

    int pkt_count;
    pcap_t *pcap_file; 
    char errBuf[PCAP_ERRBUF_SIZE]; //error buffer for opening  the pcap file
    struct pcap_pkthdr *header;
    uint8_t *packet_data;
    int protocol_type;



    if (argc < 2){ //args error checking
        printf("Error! Incorrect number of arguments\nUsage: trace <filename.pcap>\n");
		return 0;
    }

    pcap_file = pcap_open_offline(argv[1], errBuf); //open pcap file
    if(!pcap_file) { //file open error checking
        printf("%s\n", errBuf);
        return 0;
    }

    pkt_count = 1;
    while(pcap_next_ex(pcap_file, &header, (const u_char **)&packet_data) == 1 ) {

        printf("Packet number: %d Packet Len: %d\n\n", pkt_count++, header->len);


        //process ethernet
        protocol_type = print_ether_info(packet_data);

        switch(protocol_type) {
            case ARP_CODE:
                printf("ARP\n\n");
                print_arp_info(packet_data + ETHER_HEADER_LEN);
                break;
        }
    }
    //remember to pcap close
} 



int print_ether_info(uint8_t *packet_data){    
    struct ether_struct *header = (struct ether_struct *) packet_data;
    
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n",ether_ntoa((const struct ether_addr *)header->dest));
    printf("\t\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)header->src));
    printf("\t\tType: ");

    return header->type;
}

int print_arp_info(uint8_t *packet_data) {
    struct arp_struct *header = (struct arp_struct *) packet_data;
    
    printf("\tARP header\n");
    printf("\t\tOpcode: ");
    if (header->opcode == REQUEST)
        printf("Request\n");
    else if (header->opcode == REPLY)
        printf("Reply\n");

    printf("\t\tSender MAC: %s\n", ether_ntoa((const struct ether_addr *)&header->SHA));
    printf("\t\tSender IP:  %s\n", inet_ntoa(header->SPA));
    printf("\t\tTarget MAC:  %s\n", ether_ntoa((const struct ether_addr *)&header->THA));
    printf("\t\tTarget IP:  %s\n\n\n", inet_ntoa(header->TPA));


    return 0;
}
