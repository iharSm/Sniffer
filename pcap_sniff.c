#include <pcap.h>
#include </usr/include/linux/if_ether.h>
#include </usr/include/linux/ip.h>
#include </usr/include/linux/tcp.h>
#include "tcpip.h"
// gcc -o pcap_sniff ./pcap_sniff.c  -l pcap tcpip.h

void callback(u_char * args, const struct pcap_pkthdr * cap_header,
		const u_char * packet);
void unmap_ethernet_header(const u_char *packet);
void unmap_ip_header(const u_char *packet);
void unmap_tcp_header(const u_char *packet);

void pcap_lookup_sniff() {
  struct pcap_pkthdr header;
  const u_char* packet;
  pcap_t* pcap_handle;
  char* device;
  char errbuf[PCAP_ERRBUF_SIZE];
  int var;
  device = pcap_lookupdev(errbuf);
//  if (device == NULL)
//    pcap_fatal(tcp_header"pcap_lookupdev", errbuf);
  
  printf("device %s\n", device);
  pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL)
    pcap_fatal("pcap_handle", errbuf);
  
  for (var = 0; var < 3; ++var) {
    packet = pcap_next(pcap_handle, &header);
    printf("packet length %d \n", header.len);
    dump(packet, header.len);
  }
  pcap_close(pcap_handle);
}
void sniff(){
  struct pcap_pkthdr header;
  const u_char* packet;
  pcap_t* pcap_handle;
  char* device;
  char errbuf[PCAP_ERRBUF_SIZE];
  int var;
  device = pcap_lookupdev(errbuf);
  if (device == NULL)
    pcap_fatal("pcap_lookupdev", errbuf);

  printf("device %s\n", device);
  pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL)
    pcap_fatal("pcap_handle", errbuf);

  packet = pcap_loop(pcap_handle,3, callback, NULL);
  pcap_close(pcap_handle);
}

void callback(u_char *args, const struct pcap_pkthdr *cap_header,
		const u_char *packet) {
	/*struct tcp_header *t = (struct tcp_header*) packet;*/
	printf("\n\n packet [ \n");
	unmap_ethernet_header(packet);
	unmap_ip_header(packet + ETH_HEADER_LENGTH);
	unmap_tcp_header(packet + ETH_HEADER_LENGTH + sizeof(struct ip_header));
	printf("]\n\n");
	//dump(ch1,500);
}

void unmap_ethernet_header(const u_char *packet) {
	struct ethernet_header *eth_packet = (struct ethernet_header*) packet;
	int i;
	printf("ethernet layer{ \n");
	printf("  destination");
	for(i = 0; i< ETH_ADDRESS_LENGTH; i++){
		printf(": %02x",eth_packet->destination_ether_address[i]);
	}
	printf("\n  source");
	for(i = 0; i< ETH_ADDRESS_LENGTH; i++){
		printf(": %02x",eth_packet->source_ether_address[i]);
	}
	printf("\n } \n");

}

void unmap_ip_header(const u_char *packet) {
	struct ip_header *ip = (struct ip_header *) packet;l
	printf("ip layer{");
	printf("\n version: %d", ip->version);
	printf("\n ihl: %d", ip->ihl);
	printf("\n type of service: %u", (unsigned int)(ip->type_of_service));
	printf("\n total length: %hu", ntohs(ip->total_length));
	printf("\n identification: %hu", ntohs(ip->identification));
	printf("\n flags and fragment offset: %u", ip->flags_and_fragment_offset);
	printf("\n time to live: %u", ip->time_to_live);
	printf("\n protocol: %u", ip->protocol);
	printf("\n header checksum: %u", ip->header_checksum);
	printf("\n source address: %s", inet_ntoa(ip->source_address));
	printf("\n destination address: %s", inet_ntoa(ip->destination_address));
	printf("\n} \n");
}

void unmap_tcp_header(const u_char *packet) {
	struct tcp_header *tcp = (struct tcp_header *) packet;
	printf("tcp layer{");
	printf("\n source port: %hu", ntohs(tcp->source_port));
	printf("\n destination port: %hu", ntohs(tcp->destination_port));
	printf("\n sequence number: %u", ntohl(tcp->sequence_number));
	printf("\n acknowledgment number %u", ntohl(tcp->acknowledgment_number));
	printf("\n data offset %u", tcp->data_offset);
	printf("\n flags %u \n", tcp->flags);
	if(tcp->flags & fin) printf("FIN ");
	if(tcp->flags & syn) printf("SYN ");
	if(tcp->flags & rst) printf("RST ");
	if(tcp->flags & psh) printf("PSH ");
	if(tcp->flags & ack) printf("ACK ");
	if(tcp->flags & urg) printf("URG ");

	printf("\n window size %u", inet_ntoa(tcp->window_size));
	printf("\n checksum %u", ntohs(tcp->checksum));
	printf("\n urgent pointer %u", ntohs(tcp->urgent_pointer));
	printf("\n} \n");
}

int main() {
  //pcap_lookup_sniff();
  sniff();
  return 0;
}

void pcap_fatal(const char *failed_in, const char *errbuff) {
  printf("fatal error in %s: %s \n", failed_in, errbuff);
  exit(1);
}

void dump(const unsigned char *data_buffer, const unsigned int length) {
  unsigned char byte;
  unsigned int i, j;
  
  for (i = 0; i < length; i++) {
    byte = data_buffer[i];
    printf("%02x", data_buffer[i]);
    if (((i % 16) == 15) || (i == length - 1)) {
      for (j = 0; j < 15 - (i % 16); j++)
	printf("  ");
      printf("| ");
      for (j = (i - (i % 16)); j <= i; j++) {
	byte = data_buffer[j];
	if ((byte > 31) && (byte < 127))
	  printf("%c", byte);
	else
	  printf(".");
      }
      printf("\n");
    }
  }
  

}
