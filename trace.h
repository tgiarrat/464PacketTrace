

#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/in.h>

#define ARP_CODE 1544 //this is the int value of the type's bits'

#define REQUEST 256
#define REPLY 512

#define ETHER_HEADER_LEN 14

#define  ADDR_LEN 6 //6 octets, char is one octet


int print_ether_info(uint8_t *);
int print_arp_info(uint8_t *);


struct ether_struct{
    uint8_t dest[ADDR_LEN]; //destination mac addr
    uint8_t src[ADDR_LEN]; // source mac adddr
    uint16_t type; //tpye of protocol
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






