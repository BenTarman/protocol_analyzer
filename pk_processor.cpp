//
// Created by Phil Romig on 11/13/18.
//

#include "packetstats.h"

void process_network_ipv4(const u_char*, resultsC*, size_t);
void process_transport_tcp(const u_char*, resultsC*, int);
void process_transport_udp(const u_char*, resultsC*, int);

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
    TRACE << "\tPacket physical length is " << pkthdr->len;


	int MAC_dest = (packet[0] * 1280) + (packet[1] * 1024) + 
		(packet[2] * 768) + (packet[3] * 512) + (packet[5] * 256) + packet[6];
	
	int MAC_src = (packet[6] * 1280) + (packet[7] * 1024) + 
		(packet[8] * 768) + (packet[9] * 512) + (packet[10] * 256) + packet[11];

		
		int src1 = packet[6];
		int src2 = packet[7];
		int src3 = packet[8];
		int src4 = packet[9];
		int src5 = packet[10];
		int src6 = packet[11];
    
		TRACE << "\tSource MAC = " << std::hex 
			<< src1 << ":" << std::hex
			<< src2 << ":" << std::hex
			<< src3 << ":" << std::hex
			<< src4 << ":" << std::hex
			<< src5 << ":" << std::hex
			<< src6;

		int dst1 = packet[0];
		int dst2 = packet[1];
		int dst3 = packet[2];
		int dst4 = packet[3];
		int dst5 = packet[4];
		int dst6 = packet[5];

    TRACE << "\tDestination MAC = " << std::hex 
			<< dst1 << ":" << std::hex
			<< dst2 << ":" << std::hex
			<< dst3 << ":" << std::hex
			<< dst4 << ":" << std::hex
			<< dst5 << ":" << std::hex
			<< dst6;

    results->newDstMac(MAC_dest);
    results->newSrcMac(MAC_src);
	
		// see if we doing ethernet or ieee
		// int ethernetByteSize = (int)packet[12]*256 + (int)packet[13];
		// length in ieee is always less than 1500 bytes
		//uint16_t ethernetByteSize = ((uint16_t)packet[12] << 8) | packet[13];
		int ethernetByteSize = (packet[12]* 256) + packet[13];

		TRACE << "\tEther Type = " << std::to_string(ethernetByteSize);

		if (ethernetByteSize >= 1536)
		{
			//ethernet
			//doens't seem to have the preamble honestly, its throwing my flow off
			results->newEthernet(pkthdr->len);

			//same thing
			uint16_t type = ((uint16_t)packet[12] << 8) | packet[13];

			//ipv4
			if (ethernetByteSize == 0x0800)
			{
				TRACE << "\tPacket is IPv4";

				u_char* datagram = (u_char*)malloc(pkthdr->len * sizeof(u_char));

				//to make processing less of a headache just recopy each layer
				for (int i = 0; i < pkthdr->len; i++)
					datagram[i] = packet[i+14];

				process_network_ipv4(datagram, results, pkthdr->len);
			}
			else if (ethernetByteSize == 2054)
			{
				results->newARP(pkthdr->len);

			}

			//IPv6
			else if(ethernetByteSize == 34525)
			{
				results->newIPv6(pkthdr->len);
			}

			else
			{
				TRACE << "\tPacket has an unrecognized ETHERTYPE";
				results->newOtherNetwork(pkthdr->len);
			}

		}
		else
		{
			results->newIEEE(ethernetByteSize); //TODO: fix size
		}

}


void process_network_ipv4(const u_char *datagram, resultsC* results, size_t data_length)
{
	//think the assignment wants length of ip datagram to be put on this
	results->newIPv4(data_length);

	int ipv4_src1 = ((uint16_t)datagram[12] << 8) | datagram[13];
	int ipv4_src2 = ((uint16_t)datagram[14] << 8) | datagram[15];
	int ipv4_src = ((uint32_t)ipv4_src1 << 16) | ipv4_src2;
	
	int ipv4_dst1 = ((uint16_t)datagram[16] << 8) | datagram[17];
	int ipv4_dst2 = ((uint16_t)datagram[18] << 8) | datagram[19];
	int ipv4_dst = ((uint32_t)ipv4_dst1 << 16) | ipv4_dst2;

	results->newSrcIPv4(ipv4_src);
	results->newDstIPv4(ipv4_dst);

	int s1 = datagram[12];
	int s2 = datagram[13];
	int s3 = datagram[14];
	int s4 = datagram[15];

	std::string srcstring = std::to_string(s1) + "." + 
													std::to_string(s2) + "." + 
													std::to_string(s3) + "." + 
													std::to_string(s4);
				
	TRACE	 << "\tSource IP address is " << srcstring;	

	int d1 = datagram[16];
	int d2 = datagram[17];
	int d3 = datagram[18];
	int d4 = datagram[19];
	
	std::string dststring = std::to_string(d1) + "." + 
													std::to_string(d2) + "." + 
													std::to_string(d3) + "." + 
													std::to_string(d4);
				
	TRACE	 << "\tDestination IP address is " << dststring;
	

	int total_length = (uint16_t)(datagram[2] << 8) | datagram[3];

	//check if more fragment bit set
	if((datagram[6] & 32) == 32)
	{
		results->incrementFragCount();
		TRACE << "\tFRAG bit set";
	}

	//int testbit = ((datagram[6] & 32) == 32);
	//if (testbit) results->incrementFragCount();

	uint16_t transport_protocol = (uint16_t)datagram[9];

	//on transport layer we call it a packet i think
	u_char* packet = (u_char*)malloc(data_length* sizeof(u_char));

	uint8_t header_length = datagram[0] & 0x0F;


	//to make processing less of a headache just recopy each layer
	//im just assuming no options each time honestly
	for (int i = 0; i < data_length; i++)
		packet[i] = datagram[i+20];

	//ICMP
	if (transport_protocol == 1)
	{
		results->newICMP(data_length);
	}

	//TCP
	else if (transport_protocol == 6)
	{
		results->newTCP(data_length);
		process_transport_tcp(packet, results, data_length);
	}

	//UDP
	else if (transport_protocol == 17)
	{
		process_transport_udp(packet, results, data_length);
	}

	//...?
	else
	{
    results->newOtherNetwork(data_length);
	}
}


void process_transport_tcp(const u_char* packet, resultsC* results, int length)
{

	TRACE << "\t Packet is TCP";

	int src = ((uint16_t)packet[0] << 8) | packet[1];
	int dst = ((uint16_t)packet[2] << 8) | packet[3];

	//place source and destination port numbers in results
	results->newSrcTCP(src);
	results->newDstTCP(dst);

	TRACE << "\tSource port #" << std::to_string(src);
	TRACE << "\tDestination port #" << std::to_string(dst);

	//get syn and fin bits and increment if exist
	uint8_t syn_bit = packet[13] & 0x02;
	uint8_t fin_bit = packet[13] & 0x01;
	if (syn_bit) results->incrementSynCount();
	if (fin_bit) results->incrementFinCount();
	
	if (syn_bit) TRACE << "\tSYN bit set";
	if (fin_bit) TRACE << "\tFIN bit set";
}


void process_transport_udp(const u_char* packet, resultsC* results, int length)
{
	//8 bit header doesn't count i think idk
	results->newUDP(length);
	
	uint16_t src = ((uint16_t)packet[0] << 8) | packet[1];
	uint16_t dst = ((uint16_t)packet[2] << 8) | packet[3];

	//place source and destination port numbers in results
	results->newSrcUDP(src);
	results->newDstUDP(dst);
}




























