#include <pcap.h>



int main(int argc, char **argv) {

    int pkt_count;
    pcap_t *pcap_file; 
    char errBuf[PCAP_ERRBUF_SIZE]; //error buffer for opening  the pcap file
    struct pcap_pkthdr *header;
    const u_char *packet_data;

    if (argc < 2){ //args error checking
        printf("Error! Incorrect number of arguments\nUsage: trace <filename.pcap>\n");
		return 0;
    }

    pcap_file = pcap_open_offline(argv[1], errBuf); //open pcap file
    if(!pcap) { //file open error checking
        printf("%s\n", errBuf);
        return 0;
    }

    pkt_count = 1;
    while(pcap_next_ex(pcap_file, &header, &packet_data)) {

        //get packet length
        printf("Packet number: %d Packet Len: %d", pkt_count++, header->len);

        //first process ethernet

    }


    //remember to pcap close
} 