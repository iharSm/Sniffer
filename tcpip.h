/*
 * tcpip.h
 *
 *  Created on: Jun 20, 2014
 *      Author: deazz
 */
#ifndef TCPIP_H_
#define TCPIP_H_

#endif /* TCPIP_H_ */

#define ETH_ADDRESS_LENGTH	6		/* Octets in one ethernet addr	 */
#define ETH_HEADER_LENGTH	14		/* Total octets in header.	 */

struct ip_header {
	unsigned char ihl : 4;
	unsigned char version : 4;
	unsigned char type_of_service;
	unsigned short total_length;
	unsigned short identification;
	unsigned short flags_and_fragment_offset;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short header_checksum;
	unsigned int source_address;
	unsigned int destination_address;
};

struct tcp_header {
	unsigned short source_port;
	unsigned short destination_port;
	unsigned int sequence_number;
	unsigned int acknowledgment_number;
	unsigned char reserved :4;
	unsigned char data_offset :4;
	unsigned char flags;
#define fin 0x01
#define syn 0x02
#define rst 0x04
#define psh 0x08
#define ack 0x10
#define urg 0x20
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_pointer;
};

struct ethernet_header{
	unsigned char destination_ether_address[ETH_ADDRESS_LENGTH];
	unsigned char source_ether_address[ETH_ADDRESS_LENGTH];
	unsigned short packet_type;
};
