#include <pcap.h>
#include <stdint.h>
#include "trace.h"
#include <net/ethernet.h>
//#include <netinet/ether.h>
#include <arpa/inet.h>
#include "checksum.h"
#include <stdio.h> 
#include <string.h>
#include <stdlib.h>  

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

        printf("\nPacket number: %d  Packet Len: %d\n\n", pkt_count++, header->len);


        //process ethernet
        protocol_type = print_ether_info(packet_data);

        switch(protocol_type) {
            case ARP_CODE:
                print_arp_info(packet_data + ETHER_HEADER_LEN);
                break;
            case IP_CODE:
                protocol_type = print_ip_info(packet_data + ETHER_HEADER_LEN);
                //print_protocol_info(protocol_type, packet_data + ETHER_HEADER_LEN + IP_HEADER_LEN);
                break;   
            default:
                printf("Unknown Protocol type: %d\n", protocol_type);
        }

    }
    pcap_close(pcap_file);
    return 0;
} 

int print_ether_info(uint8_t *packet_data){    
    struct ether_struct *header = (struct ether_struct *) packet_data;
    
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n",ether_ntoa((const struct ether_addr *)header->dest));
    printf("\t\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)header->src));
    printf("\t\tType: ");

    return header->type;
}

//returns protocol number
int print_ip_info(uint8_t *packet_data ){
    struct ip_struct *header = (struct ip_struct *)packet_data;
    int ip_version = (header->version_and_ihl >> 4) & 0xF;
    int header_len = ((header->version_and_ihl) & 0xF) * 4;//must multiply by 4 to get the correct number of bytes. if not it only gives the num of 32 bit words
    int diffserv_bits = ((header->dscp_and_ecn >> 2) & 0x3F);
    int ecn_bits = ((header->dscp_and_ecn) & 0x3);

    printf("IP\n\n");
    printf("\tIP Header\n");
    printf("\t\tIP Version: %d\n", ip_version);
    printf("\t\tHeader Len (bytes): %d\n",header_len);
    printf("\t\tTOS subfields:\n");
    printf("\t\t   Diffserv bits: %d\n", diffserv_bits);
    printf("\t\t   ECN bits: %d\n", ecn_bits);
    printf("\t\tTTL: %d\n", header->ttl);
    
    printf("\t\tProtocol: ");
    if (header->protocol == ICMP)
        printf("ICMP\n");
    else if (header->protocol == TCP)
        printf("TCP\n");
    else if (header->protocol == UDP)
        printf("UDP\n");
    else 
        printf("Unknown\n");

    printf("\t\tChecksum: ");
    if ((in_cksum((unsigned short *)header, header_len)) == 0 )
        printf("Correct (0x%04hx)\n", ntohs(header->header_checksum));
    else
        printf("Incorrect (0x%04hx)\n", ntohs(header->header_checksum));
    printf("\t\tSender IP: %s\n", inet_ntoa(header->src_ip));
    printf("\t\tDest IP: %s\n", inet_ntoa(header->dest_ip));
    
    if (header->protocol == ICMP)
        print_icmp_info(packet_data + IP_HEADER_LEN, ip_version);
    else if (header->protocol == TCP)
        print_tcp_info(packet_data+ IP_HEADER_LEN, header);
    else if (header->protocol == UDP)
        print_udp_info(packet_data+ IP_HEADER_LEN);

    return header->protocol;
}


int print_arp_info(uint8_t *packet_data) {
    struct arp_struct *header = (struct arp_struct *) packet_data;
    
    printf("ARP\n\n");
    printf("\tARP header\n");
    printf("\t\tOpcode: ");
    if (header->opcode == ARP_REQUEST)
        printf("Request\n");
    else if (header->opcode == ARP_REPLY)
        printf("Reply\n");

    printf("\t\tSender MAC: %s\n", ether_ntoa((const struct ether_addr *)&header->SHA));
    printf("\t\tSender IP: %s\n", inet_ntoa(header->SPA));
    printf("\t\tTarget MAC: %s\n", ether_ntoa((const struct ether_addr *)&header->THA));
    printf("\t\tTarget IP: %s\n\n", inet_ntoa(header->TPA));


    return 0;
}

int print_icmp_info(uint8_t *packet_data, int ip_version) {
    struct icmp_struct *header = (struct icmp_struct *) packet_data;
    
    printf("\n\tICMP Header\n");
    printf("\t\tType: ");
    if (ip_version == 11) 
        printf("109\n");
    else if (header->type == ICMP_REQUEST)
        printf("Request\n");
    else if (header->type == ICMP_REPLY)
        printf("Reply\n");
    else
        printf("Unknown ICMP type\n");
    return 0; 
}

int print_udp_info(uint8_t *packet_data){
    struct udp_struct *header = (struct udp_struct *) packet_data;
    int src = ntohs(header->src);
    int dest = ntohs(header->dest);

    printf("\n\tUDP Header\n");
    printf("\t\tSource Port:  ");
    if (src == 53) 
        printf("DNS\n");
    else 
        printf("%d\n", src);
    printf("\t\tDest Port:  ");
    if (dest == 53) 
        printf("DNS\n");
    else 
        printf("%d\n", dest);
    return 0;
}

int print_tcp_info(uint8_t *packet_data, struct ip_struct *ip_header) {
    struct tcp_struct *header = (struct tcp_struct *) packet_data;
    struct tcp_pseudo_struct pseudo_struct;
    uint8_t flags = header->flags;
    int syn = (flags >> 1) & 0x1; 
    int rst = (flags >> 2) & 0x1;
    int fin = flags & 0x1;
    int ack = (flags >> 4) & 0x1;
    

    printf("\n\tTCP Header\n");
    printf("\t\tSource Port:  ");
    print_port(ntohs(header->src_port));
    printf("\t\tDest Port:  ");
    print_port(ntohs(header->dest_port));
    printf("\t\tSequence Number: %u\n", ntohl(header->seq_number) );
    printf("\t\tACK Number: %u\n", ntohl(header->ack_num));
    printf("\t\tData Offset (bytes): %d\n", ((header->offset_and_reserved >> 4) & 0xF) * 4);
    printf("\t\tSYN Flag: %s\n", (syn ? "Yes" : "No"));
    printf("\t\tRST Flag: %s\n", (rst ? "Yes" : "No"));
    printf("\t\tFIN Flag: %s\n", (fin ? "Yes" : "No"));
    printf("\t\tACK Flag: %s\n", (ack ? "Yes" : "No"));
    printf("\t\tWindow Size: %d\n",ntohs(header->window_size));

    //cehcksum
    pseudo_struct.src_addr = ip_header->src_ip;
    pseudo_struct.dest_addr = ip_header->dest_ip;
    pseudo_struct.reserved = 0;
    pseudo_struct.protocol = ip_header->protocol;
    pseudo_struct.segment_length = htons(ntohs(ip_header->total_length) - IP_HEADER_LEN);

    tcp_checksum(header, pseudo_struct);

    return 0;
}

int tcp_checksum(struct tcp_struct *tcp_header, struct tcp_pseudo_struct pseudo_header) {
    int buffer_len = (ntohs(pseudo_header.segment_length) + PSEUDO_HEADER_LEN);
    char *tcp_buffer = calloc(buffer_len, sizeof(char));

    //copy pseudo + tcp header + data into buffer
    memcpy(tcp_buffer, &pseudo_header, PSEUDO_HEADER_LEN);
    memcpy(tcp_buffer + PSEUDO_HEADER_LEN, tcp_header, ntohs(pseudo_header.segment_length));

    if (in_cksum((unsigned short *)tcp_buffer, buffer_len) == 0) 
        printf("\t\tChecksum: Correct (0x%04hx)\n", ntohs(tcp_header->checksum_value));
    else 
        printf("\t\tChecksum: Incorrect (0x%04hx)\n", ntohs(tcp_header->checksum_value));
    free(tcp_buffer);
    return 0;
}

int print_port(int port_num) {
    if (port_num == HTTP) 
        printf("HTTP\n");
    else if (port_num == TELNET)
        printf("TELNET\n");
    else if (port_num == FTP)
        printf("FTP\n");
    else if (port_num == POP3)
        printf("POP3\n");
    else if (port_num == SMTP)
        printf("SMTP\n");
    else
        printf("%d\n", port_num);

    return 0;
}