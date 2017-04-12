#include <stdint.h>


typedef struct ehter_struct{
    char dest[MAC_LEN]; //destination mac addr
    char src[MAC_LEN]; // source mac adddr
    uint16_t type; //tpye of protocol
}__attribute__((packed)); 


int print_ether_info(uint8_t *);