

#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#define ARP_CODE 1544 //this is the int value of the type's bits'
#define IP_CODE 8
#define ICMP 1
#define TCP 6
#define UDP 17

#define HTTP 80
#define TELNET 23
#define FTP 21
#define POP3 110
#define SMTP 25

#define ARP_REQUEST 256
#define ARP_REPLY 512
#define ICMP_REQUEST 8
#define ICMP_REPLY 0

#define ETHER_HEADER_LEN 14
#define IP_HEADER_LEN 20 //not counting options, i beleive we  dont have them'
#define PSEUDO_HEADER_LEN 14

#define  ADDR_LEN 6 //6 octets, char is one octet



struct ether_struct{
    uint8_t dest[ADDR_LEN]; //destination mac addr
    uint8_t src[ADDR_LEN]; // source mac adddr
    uint16_t type; //tpye of protocol
}__attribute__((packed)); 

struct ip_struct{
    uint8_t version_and_ihl; //contains the IP verison and header length
    uint8_t dscp_and_ecn; //contains TOS subfields
    uint16_t total_length; //total legth
    uint16_t id;
    uint16_t flags_and_offset; //contains flags and fragment offset
    uint8_t ttl; //time to live
    uint8_t protocol;
    uint16_t header_checksum;
    struct in_addr src_ip;
    struct in_addr dest_ip;
    //uint32_t options; //this might be too big, not sure
}__attribute__((packed)); 

struct arp_struct{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hard_addr_len; //hardware address length
    uint8_t prot_addr_len; //protocol address length
    uint16_t opcode; //256 for request 512 for reply
    struct ether_addr SHA; //sender hardware address (is MAC)
    struct in_addr SPA; //sender protocol address (is ipv4)
    struct ether_addr THA; //target hardware
    struct in_addr TPA; //target protocol
}__attribute__((packed)); 

struct icmp_struct{
    uint8_t type;
    uint8_t code; 
    uint16_t checksum;
    uint32_t rest;
}__attribute__((packed));

struct tcp_pseudo_struct{
    struct in_addr src_addr; //from ip header
    struct in_addr dest_addr; //from ip header
    uint8_t reserved; 
    uint8_t protocol; //from ip header
    uint16_t segment_length; //computed
}__attribute__((packed));

struct tcp_struct{
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_number;
    uint32_t ack_num;
    uint8_t offset_and_reserved; //includes NS flag. make sure to mask
    uint8_t flags; // SYN, RST, FIN, ACK
    uint16_t window_size; 
    uint16_t checksum_value;
    uint16_t urgent_pointer;
}__attribute__((packed));

struct udp_struct {
    uint16_t src;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
}__attribute__((packed));


int print_ether_info(uint8_t *);
int print_ip_info(uint8_t *);
int print_arp_info(uint8_t *);
int print_icmp_info(uint8_t *, int);
int print_udp_info(uint8_t *);
int print_tcp_info(uint8_t *, struct ip_struct *);
int tcp_checksum(struct tcp_struct*, struct tcp_pseudo_struct);
int print_port(int);






