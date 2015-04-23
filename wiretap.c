/********************************
 * Jacob Henderson (jacohend)	*
 *******************************/

#include <pcap/pcap.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <time.h>

#define DHCP_UDP_OVERHEAD	(20 + 8)
#define DHCP_SNAME_LEN		64
#define DHCP_FILE_LEN		128
#define DHCP_FIXED_NON_UDP	236
#define DHCP_FIXED_LEN		(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
#define DHCP_MTU_MAX		1500
#define DHCP_OPTION_LEN		(DHCP_MTU_MAX - DHCP_FIXED_LEN)

struct dhcp_packet {
	u_int8_t  op;	
	u_int8_t  htype;	
	u_int8_t  hlen;		
	u_int8_t  hops;		
	u_int32_t xid;		
	u_int16_t secs;		
	u_int16_t flags;	
	struct in_addr ciaddr;	
	struct in_addr yiaddr;	
	struct in_addr siaddr;	
	struct in_addr giaddr;	
	unsigned char chaddr[16];	
	char sname[DHCP_SNAME_LEN];	
	char file[DHCP_FILE_LEN];	
	unsigned char options[DHCP_OPTION_LEN];
};

#define ARRAY_LENGTH 100
#define MAX_ADDRESS_LEN 18
pcap_t *handle;
struct addr_array* addresses;
int array_length;
int expand_count;
int max_length=0, min_length=0;
float total_size=0;
int number_of_packets=0;
long tstart = 0, tfinish = 0;

struct addr_array{
    char addr[MAX_ADDRESS_LEN];
    int num;
};

//Prints the array after done
int array_print(){
    int i = 0;
    for(i = 0; i < array_length - 1; i++){
        printf("%-25s%d\n", addresses[i].addr, addresses[i].num);
    }
}

//Recieves error message, prints it, then terminate the progroam
void error(const char *message) {
	fprintf(stderr, message);
	exit(1);
}

//Insert term into array. 
int array_insert(char* term){
    int i = 0;
    for(i = 0; i < array_length; i++){     //if the term is already here, increment it
        if (strcmp(addresses[i].addr, term) == 0){
            addresses[i].num++;
            return 1;
        }
    }
    struct addr_array insert;              //if the term is new, add it
    strcpy(insert.addr, term);
    insert.num = 1;
    addresses[array_length - 1] = insert;
    array_length++;
    if (array_length >= 99){
        expand_count++;
        struct addr_array* tmp;
        tmp = (struct addr_array*)realloc(addresses, (expand_count * (sizeof(struct addr_array) * ARRAY_LENGTH)));
        if (tmp == NULL){
			error("Reallocation failed\n");
        }
        addresses = tmp;
    }
    return 0;
}

//Uses array_insert to insert MAC address
void insert_mac(void *address) {
    array_insert(ether_ntoa((struct ether_addr *)address));
}

//Uses array_insert to insert IP address
void insert_ip(struct in_addr* address){
    char ip_address[MAX_ADDRESS_LEN];
    inet_ntop(AF_INET, address, ip_address, INET_ADDRSTRLEN);
    array_insert(ip_address);
}

//Packet Capture Summary
void pkt_capt_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *ethernet = (struct ether_header *)packet;
    if(tstart == 0){
		tstart = header->ts.tv_sec;
	}
	tfinish = header->ts.tv_sec;
	number_of_packets++;
}

//Mac (Ethernet) Source Address
void mac_src_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *ethernet = (struct ether_header *)packet;
    insert_mac(ethernet->ether_shost);
}

//Mac (Ethernet) Destination Address
void mac_dest_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *ethernet = (struct ether_header *)packet;
    insert_mac(ethernet->ether_dhost);
}

//Network Layer Protocol
void NLP_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *ethernet = (struct ether_header *)packet;
	int port = ethernet->ether_type;
	char buffer[3];
	
	if(ntohs(ethernet->ether_type) == ETHERTYPE_IP){
		array_insert("IP");
	}
	else{
		sprintf(buffer, "%x", ntohs(ethernet->ether_type));
		array_insert(buffer);
	}
}

//IP Source Address
void ip_src_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ether_header *ethernet = (struct ether_header *)packet;
    struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		insert_ip(&(ip->ip_src));
	}
}


//IP Destination Address
void ip_dest_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ether_header *ethernet = (struct ether_header *)packet;
    struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		insert_ip(&(ip->ip_dst));
	}
}

//Transport Layer Protocols
void transport_layer_protocol_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ether_header *ethernet = (struct ether_header *)packet;
	
	struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	int type = ip->ip_p;
	char buffer[8];
	
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){	
		switch (type) {
			case 1:
				sprintf(buffer, "%d", type);
				array_insert(buffer);
				break;
			case 2:
				sprintf(buffer, "%d", type);
				array_insert(buffer);
				break;
			case 6:
				array_insert("TCP");
				break;
			case 17:
				array_insert("UDP");
				break;
		}
	}
}

//TCP flags
void tcp_flags_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	struct ether_header *ethernet = (struct ether_header *)packet;
	
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		if(ip->ip_p == 6){
			struct tcphdr *tcphdr = (struct tcphdr *) (packet+sizeof(struct ether_header) + sizeof(struct ip));
			if(tcphdr->ack == 1){
				array_insert("ACK");
			}
			if(tcphdr->urg == 1){
				array_insert("URG");
			}
			if(tcphdr->fin == 1){
				array_insert("FIN");
			}		
			if(tcphdr->psh == 1){
				array_insert("PSH");
			}
			if(tcphdr->syn == 1){
				array_insert("SYN");
			}
			if(tcphdr->rst == 1){
				array_insert("RST");
			}
		}
	}
}

//TCP Source
void tcp_src_ports_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	struct ether_header *ethernet = (struct ether_header *)packet;
	
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		if(ip->ip_p == 6){
			char buffer[8];
			struct tcphdr *tcphdr = (struct tcphdr *) (packet+sizeof(struct ether_header) + sizeof(struct ip));
			sprintf(buffer, "%d", ntohs(tcphdr->source));
			array_insert(buffer);
		}
	}
}

//TCP Destination
void tcp_dest_ports_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	struct ether_header *ethernet = (struct ether_header *)packet;
	
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		
		if(ip->ip_p == 6){
			char buffer[8];
			struct tcphdr *tcphdr = (struct tcphdr *) (packet+sizeof(struct ether_header) + sizeof(struct ip));
			sprintf(buffer, "%d", ntohs(tcphdr->dest));
			array_insert(buffer);
		}
	}
}

//UDP Source
void udp_src_ports_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	struct ether_header *ethernet = (struct ether_header *)packet;
	
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		
		if(ip->ip_p == 17){
			char buffer[8];
			struct udphdr *udphdr = (struct udphdr *) (packet+sizeof(struct ether_header) + sizeof(struct ip));
			sprintf(buffer, "%d", ntohs(udphdr->source));
			array_insert(buffer);
		}
	}
}

//UDP destination
void udp_dest_ports_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ip* ip = (struct ip*) (packet + sizeof(struct ether_header));
	struct ether_header *ethernet = (struct ether_header *)packet;
	
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		if(ip->ip_p == 17){
			char buffer[8];
			struct udphdr *udphdr = (struct udphdr *) (packet+sizeof(struct ether_header) + sizeof(struct ip));
			sprintf(buffer, "%d", ntohs(udphdr->dest));
			array_insert(buffer);
		}
	}
}

//UDP Checksum
void udp_checksum_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ip* ip;
    ip = (struct ip*) (packet + sizeof(struct ether_header));
    int type = ip->ip_p;
    if (type == 17){
        unsigned long sum = 0;
        unsigned short *ip_src =(void*) &(ip->ip_src.s_addr);
        unsigned short *ip_dst=(void*)&(ip->ip_dst.s_addr);
        int i = 0;
        struct udphdr *udp = (struct udphdr *) (packet+sizeof(struct ether_header) + ip->ip_hl * 4);
        if (udp->check == 0){
            array_insert("Omit checksum");
        }
        const unsigned short *buf = (unsigned short *)udp;
        int length = ntohs(udp->len);
        int len;
        unsigned short blah2 = udp->check;        
        for(len = length; len > 1; len-= 2){    
            sum += *buf++;         //add byte from header
            if (sum & 0x80000000){ //add words 
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
        }
        if (len&1){  //if byte length of header is odd, add a zero
            sum += *((unsigned char *)buf);
        }
        sum +=  *(ip_src++);    //start pseudoheader, 2 bytes
        sum += *ip_src;         //2 bytes
        sum += *(ip_dst++);     //2 bytes
        sum += *ip_dst;         //2 bytes
        sum += htons(17) + htons(length); //add UDP length and protocol 
        while (sum >> 16){
            sum = (sum & 0xFFFF) + (sum >> 16); //slice off first 16 bit, add the carry bit
        }
        unsigned short checksum = (unsigned short) ~sum;
        if (checksum){
            array_insert("Correct checksum");
        }else{
            array_insert("Incorrect checksum");
        }
    }       
}
//Packet Summary
void packet_summary_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	if(max_length == 0 || min_length == 0){
		max_length = header->len;
		min_length = header->len;
	}
	
	if(header->len > max_length){
		max_length = header->len;
	}
	
	if(header->len < min_length){
		min_length = header->len;
	}
	total_size  = total_size + header->len;
}

//An attempt to find DHCP servers and clients for extra credit
void dhcp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct dhcp_packet *dhcp = (struct dhcp_packet*) (packet + sizeof(struct ether_header));
	struct ether_header *ethernet = (struct ether_header *)packet;

	if(dhcp->hops == 72 && dhcp->flags == 0){
		insert_ip((struct in_addr *) &dhcp->ciaddr);
		insert_mac(ethernet->ether_dhost);
	}
}


int main (int argc, char** argv){
	if (argc < 2){
		error("No input files\n");
	}
	char err[PCAP_ERRBUF_SIZE];
	int i = 0;
	time_t result;
	struct tm* brokentime;
	
	expand_count = 1;
	for(i = 0; i < 15; i++){
		if ((handle = pcap_open_offline(argv[1], err)) == NULL){
			error("Cannot open pcap dump file\n");
		}
        if (pcap_datalink(handle) != DLT_EN10MB){
            error("pcap dump not in ethernet format\n");
        }
        /* initialize array for storing statistics */
        addresses = (struct addr_array*)malloc(sizeof(struct addr_array) * ARRAY_LENGTH);
        array_length = 1;
        switch(i){
			case 0:
                printf("\nPackat Capture Summary:\n");
                if (pcap_loop(handle, -1, pkt_capt_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
				printf("Capture start date: %s", ctime((const time_t*)&tstart));
				printf("Capture duration: %ld seconds\n", tfinish-tstart);
				printf("Packets in capture: %d packets\n", number_of_packets);
                break;
            case 1:
                printf("\nSource Ethernet Address:\n");
				printf("MAC Address\t\t#packets\n--------------------------------\n");
                if (pcap_loop(handle, -1, mac_src_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
            case 2:
                printf("\nDestination Mac Address:\n");
				printf("MAC Address\t\t#packets\n--------------------------------\n");
                if (pcap_loop(handle, -1, mac_dest_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 3:
                printf("\nNetwork Layer Protocol Summary:\n");
				printf("Protocol\t\t#packets\n--------------------------------\n");
                if (pcap_loop(handle, -1, NLP_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;				
            case 4:
                printf("\nSource IP Address:\n");
				printf("IP Address\t\t#packets\n--------------------------------\n");
                if (pcap_loop(handle, -1, ip_src_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
            case 5:
                printf("\nDestination IP Address:\n");
				printf("IP Address\t\t#packets\n--------------------------------\n");
                if (pcap_loop(handle, -1, ip_dest_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 6:
				printf("\nTransport Layer Protocol:\n");
				printf("Protocol\t\t#packets\n--------------------------------\n");
				if (pcap_loop(handle, -1, transport_layer_protocol_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 7:
				printf("\nTCP Flag:\n");
				printf("Flag\t\t\t#packets\n--------------------------------\n");
				if (pcap_loop(handle, -1, tcp_flags_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;				
			case 8:
				printf("\nTCP source port:\n");
				printf("Port\t\t#packets\n--------------------------------\n");
				if (pcap_loop(handle, -1, tcp_src_ports_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 9:
				printf("\nTCP destination port:\n");
				printf("Port\t\t#packets\n--------------------------------\n");
				if (pcap_loop(handle, -1, tcp_dest_ports_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
				
			case 10:
				printf("\nUDP source port:\n");
				printf("Port\t\t#packets\n--------------------------------\n");
				if (pcap_loop(handle, -1, udp_src_ports_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 11:
				printf("\nUDP destination port:\n");
				printf("Port\t\t#packets\n--------------------------------\n");
				if (pcap_loop(handle, -1, udp_dest_ports_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 12:
				printf("\nUDP Checksum Summary:\n");
				if (pcap_loop(handle, -1, udp_checksum_callback, NULL) < 0){
                    error("packets nonexistent or exhausted\n");
                }
                break;
			case 13:
				printf("\nPacket Summary:\n");
				if (pcap_loop(handle, -1, packet_summary_callback, NULL) < 0){
					error("packets nonexistent or exhausted\n");
                }
				printf("Minimum Packet Size:\t%d\n", min_length);
				printf("Maximum Packet Size:\t%d\n", max_length);
				printf("Average Packet Size:\t%0.2f\n", total_size/(float)number_of_packets);
				break;
			case 14:
				printf("\nDHCP:\n");
				if (pcap_loop(handle, -1, dhcp, NULL) < 0){
					error("packets nonexistent or exhausted\n");
				}
		}
		//Close, print array then free memory.
		pcap_close(handle); 
		array_print();
		free(addresses);
	}
	return 1;
}
