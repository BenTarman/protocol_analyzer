//
// Created by Phil Romig on 11/13/18.
//

#include "packetstats.h"

void process_network_ipv4(const u_char*, resultsC*, size_t);
void process_transport_tcp(const u_char*, resultsC*, int);

// ****************************************************************************
// * pk_processor()
// *  Most/all of the work done by the program will be done here (or at least it
// *  it will originate here). The function will be called once for every
// *  packet in the savefile.
// ****************************************************************************
void pk_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    resultsC* results = (resultsC*)user;
    results->incrementTotalPacketCount();
    DEBUG << "Processing packet #" << results->packetCount() << ENDL;
    char s[256]; 
		bzero(s,256); bcopy(ctime(&(pkthdr->ts.tv_sec)),s,strlen(ctime(&(pkthdr->ts.tv_sec)))-1);

    TRACE << "\tPacket timestamp is " << s;
    TRACE << "\tPacket capture length is " << pkthdr->caplen ;
    TRACE << "\tPacket physical length is " << pkthdr->len ;

		
		//see if we doing ethernet or ieee
	//	int ethernetByteSize = (int)packet[12]*256 + (int)packet[13];
		//length in ieee is always less than 1500 bytes
		uint16_t ethernetByteSize = ((uint16_t)packet[12] << 8) | packet[13];

		if (ethernetByteSize > 1500)
		{
			//ethernet
			//doens't seem to have the preamble honestly, its throwing my flow off
			results->newEthernet(ethernetByteSize); //TODO: FIX SIZE

			//same thing
			uint16_t type = ((uint16_t)packet[12] << 8) | packet[13];

			//ipv4
			if (type == 0x0800)
			{
				u_char* datagram = (u_char*)malloc(pkthdr->len * sizeof(u_char));

				//to make processing less of a headache just recopy each layer
				for (int i = 0; i < pkthdr->len; i++)
					datagram[i] = packet[i+14];

				process_network_ipv4(datagram, results, pkthdr->len);
			}
		}

		printf("\n\n");
}



void process_network_ipv4(const u_char *datagram, resultsC* results, size_t data_length)
{
	uint16_t length = ((uint16_t)datagram[2] << 8) | datagram[3];

	//think the assignment wants length of ip datagram to be put on this
	results->newIPv4(length);

	uint16_t transport_protocol = (uint16_t)datagram[9];


				

	//on transport layer we call it a packet i think
	u_char* packet = (u_char*)malloc(data_length* sizeof(u_char));


	uint8_t header_length = datagram[0] & 0xF;

	//to make processing less of a headache just recopy each layer
	for (int i = 0; i < data_length; i++)
		packet[i] = datagram[i+header_length];

	//ICMP
	if (transport_protocol == 1)
	{

	}

	//TCP
	else if (transport_protocol == 6)
	{

		process_transport_tcp(packet, results, length);

	}

	//UDP
	else if (transport_protocol == 17)
	{

	}

	//...?
	else
	{

	}



}


void process_transport_tcp(const u_char* packet, resultsC* results, int length)
{
	//uint8_t t = (int)(packet[12] - (packet[12]%16)) / 4;
	uint8_t data_offset = packet[12] >> 4;
	results->newTCP(length - data_offset);


	uint16_t src = ((uint16_t)packet[0] << 8) | packet[1];
	uint16_t dst = ((uint16_t)packet[2] << 8) | packet[3];

	//place source and destination port numbers in results
	results->newSrcTCP(src);
	results->newDstTCP(dst);

	//get syn and fin bits and increment if exist
	uint8_t syn_bit = packet[13] & 0x02;
	uint8_t fin_bit = packet[13] & 0x01;
	if (syn_bit) results->incrementSynCount();
	if (fin_bit) results->incrementFinCount();
}






























