/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

// Two Global Variables

struct packet_buffer *_pBuf = NULL;
struct arp_cache *_arpCache = NULL;

void addIntoARPCache(uint32_t ipAddr, unsigned char* macAddr) {
	struct arp_cache* arpCachePtr = _arpCache;
	struct arp_cache* prevArpCachePtr = arpCachePtr;
	
	while(arpCachePtr != NULL) {
		if(arpCachePtr->ip == ipAddr) {
			strncpy((char*)arpCachePtr->mac, (char*)macAddr, ETHER_ADDR_LEN);
		}
		prevArpCachePtr = arpCachePtr;
		arpCachePtr = arpCachePtr->next;
	}
	if(arpCachePtr == NULL) {
		// This IP was not found in the cache. So add a new node
		struct arp_cache* arpCacheNode = (struct arp_cache*)malloc(sizeof(struct arp_cache));
		arpCacheNode->ip = ipAddr;
		strncpy((char*)arpCacheNode->mac, (char*)macAddr, ETHER_ADDR_LEN);
		arpCacheNode->next = NULL;
		if(_arpCache == NULL) {
			// First Node
			_arpCache = arpCacheNode;
		} else {
			// Add node at the end
			prevArpCachePtr->next = arpCacheNode;
		}
	}
}

void dl_local_handleARPResponse(struct sr_instance* sr, 
        uint8_t* packet/* lent */,
        unsigned int len,
		char* interface) 
{
	struct sr_ethernet_hdr* ethHdr = (struct sr_ethernet_hdr*)packet;
	struct sr_arphdr* arpHdr = (struct sr_arphdr*)(packet+sizeof(struct sr_ethernet_hdr));
	
	uint32_t ipAddr = arpHdr->ar_sip;
	unsigned char* macAddr = arpHdr->ar_sha;
	
	// Populate the IP and MAC in the ARP Cache
	addIntoARPCache(ipAddr, macAddr);
	
	// Iterate through the IP packet buffer list to get corresponding buffer list
	struct packet_buffer* ipBufPtr = _pBuf;
	struct packet_buffer* prevIPBufPtr = ipBufPtr;
	while(ipBufPtr != NULL) {
		if(ipBufPtr->destIp == ipAddr) {
			struct arp_req_details* bufPtr = ipBufPtr->packetListHead;
			while(bufPtr != NULL) {
				// Construct EthernetHeader + IPHeader and send this packet
				struct sr_ethernet_hdr tempEthHdr;
				// NOTE: Here we need to use memcpy instead of strncpy because the data type for MAC addresses is different in "sr_if" and EthernetHeader structures
				memcpy(tempEthHdr.ether_dhost, macAddr, ETHER_ADDR_LEN);
				memcpy(tempEthHdr.ether_shost, sr_get_interface(sr, bufPtr->arpRequestPacketDetails->interface)->addr, ETHER_ADDR_LEN);
				ethHdr->ether_type = htons(ETHERTYPE_IP); // TODO: For now, assume that only Network Layer packets buffered!
				
				unsigned int fullPacketLen = sizeof(tempEthHdr) + bufPtr->ipPacketDetails->len;
				uint8_t* fullPacket = (uint8_t*)malloc(fullPacketLen);
				memcpy(fullPacket, &tempEthHdr, sizeof(tempEthHdr));
				memcpy(fullPacket+sizeof(tempEthHdr), bufPtr->ipPacketDetails->packet, bufPtr->ipPacketDetails->len);
				
				// We can use the same interface that was used to send the ARP request.
				sr_send_packet(sr, fullPacket, fullPacketLen, bufPtr->arpRequestPacketDetails->interface);
				
				// free all memory
				//free(bufPtr->ipPacketDetails->packet);
				//free(bufPtr->arpRequestPacketDetails->packet);
				//free(fullPacket);
				
				struct arp_req_details* tempPtr = bufPtr;
				bufPtr = bufPtr->next;
				free(tempPtr);
			}
			// Remove this IP node from the Packet buffer
			prevIPBufPtr->next = ipBufPtr->next;
			free(ipBufPtr);
			break;
		}
		prevIPBufPtr = ipBufPtr;
		ipBufPtr = ipBufPtr->next;
	}
}
 

/*--------------------------------------------------------------------- 
 * Method: dl_handleARPPacket
 * Scope: Local
 * Layer: DataLink Layer
 * 
 * Handles all ARP packets that are recieved by this router.
 *---------------------------------------------------------------------*/
struct packet_details* dl_handleARPPacket(struct sr_instance* sr,uint8_t * packet/* lent */,
        unsigned int len,char* interface) 
{
		struct sr_ethernet_hdr* e_hdr = (struct sr_ethernet_hdr*)packet;
		struct sr_arphdr*       a_hdr = (struct sr_arphdr*)(packet + sizeof(struct sr_ethernet_hdr));
		struct sr_if* iface = sr_get_interface(sr, interface);
		int type = -1;
		if(a_hdr->ar_op == htons(ARP_REQUEST)) {
			type = 0;
                        printf("\nReceived ARP Request\n");
                        z_printARPpacket(packet, len);
                } else if(a_hdr->ar_op == htons(ARP_REPLY)) {
                        printf("\nReceived ARP Response\n");
                        z_printARPpacket(packet, len);
			type = 1;
		}
		switch(type){
			case 0:
				if ((a_hdr->ar_tip == iface->ip )) {
					addIntoARPCache(a_hdr->ar_sip,a_hdr->ar_sha);
					memcpy(e_hdr->ether_dhost,e_hdr->ether_shost,ETHER_ADDR_LEN); /* destination ethernet address */
					a_hdr->ar_op=htons(ARP_REPLY);
					memcpy(a_hdr->ar_tha,a_hdr->ar_sha,ETHER_ADDR_LEN);
					a_hdr->ar_tip=a_hdr->ar_sip;
					memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);// Source Hardware Address
					memcpy(a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);// Source Hardware Address
					
					a_hdr->ar_sip=iface->ip; 
					// Construct a packet buffer = EthernetHeader + ArpHeader
					struct packet_details *retPacketDetails = (struct packet_details *)malloc(sizeof(struct packet_details));
					retPacketDetails->len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
					retPacketDetails->packet = (uint8_t *)malloc(retPacketDetails->len);
					memcpy(retPacketDetails->packet, e_hdr, sizeof(struct sr_ethernet_hdr)); // Ethernet Header
					memcpy(retPacketDetails->packet+sizeof(struct sr_ethernet_hdr), a_hdr, sizeof(struct sr_arphdr)); // ARP Header
					
					return retPacketDetails;
				}
				else {
					addIntoARPCache(a_hdr->ar_sip,a_hdr->ar_sha);
				}
				break;
			case 1:
				dl_local_handleARPResponse(sr, packet, len, interface);
				break;
		}
	return NULL;
}


uint16_t computeCheckSum(uint8_t *buff, uint16_t len_header)
{
       uint16_t word16;
       uint32_t sum=0;
       uint16_t i;

       /* make 16 bit words out of every two adjacent 8 bit words in the packet
                and add them up */
       for (i=0;i<len_header;i=i+2){
			   word16=((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
			   sum = sum + (uint32_t) word16;
       }

       /* take only 16 bits out of the 32 bit sum and add up the carries */
       while (sum>>16)
         sum = (sum & 0xFFFF)+(sum >> 16);

       /* one's complement the result */
       sum = ~sum;

       return htons(((uint16_t) sum));
}

uint16_t verifyCheckSum(uint8_t *buff, uint16_t len_header, uint16_t testSum)
{
       uint16_t word16;
       uint32_t sum=0;
       uint16_t i;

       /* make 16 bit words out of every two adjacent 8 bit words in the packet
                and add them up */
       for (i=0;i<len_header;i=i+2){
			   word16=((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
			   sum = sum + (uint32_t) word16;
       }

       /* take only 16 bits out of the 32 bit sum and add up the carries */
       while (sum>>16)
         sum = (sum & 0xFFFF)+(sum >> 16);

       /* one's complement the result */
       sum = ~sum;
       
       if(testSum == htons((uint16_t)sum))
			return 1;
		else 
			return 0;

}


/*
uint16_t icmp_checksum( uint8_t type,uint8_t code,uint16_t id,uint16_t seq)
{
       register uint16_t sum;
       uint16_t comp = 0xFF;
   sum = (( ((type^comp)&(code^comp)) & ((id^comp) &(seq^comp)) )^comp);
   return ~sum;
}
*/

/*--------------------------------------------------------------------- 
 * Method: checkSum
 * Scope: Local
 * Layer: Network Layer
 * 
 * Checks the checksum for a given packet.
 *---------------------------------------------------------------------*/
int checkSum(uint16_t* packet, unsigned int len)
{
	// TODO: hack
	if(1) {
		return 1;
	}
	uint16_t checksum = 0x0;
	int count = 0;
	
	while(count < len/sizeof(u_int16_t))
	{
		checksum += *packet;
		packet++;
	}
	if(checksum == 0xFF)
		return 1;
	else 
		return 0;
}/* end of checksum*/ 
 
/*--------------------------------------------------------------------- 
 * Method: computeCheckSum
 * Scope: Local
 * Layer: Network Layer
 * 
 * Calculates the checksum for a given packet.
 *---------------------------------------------------------------------*/
//TODO: renamed Kunal's function from computeCheckSum to computeCheckSum1
uint16_t computeCheckSum1(uint16_t* packet, unsigned int len)
{
	uint16_t checksum = 0x0;
	int count = 0;
	
	while(count < len/sizeof(u_int16_t))
	{
		checksum += *packet; 
		packet++;
	}
	return checksum;
}/* end of computechecksum*/

/*--------------------------------------------------------------------- 
 * Method: check_self
 * Scope: Local
 * Layer: Network Layer
 * 
 * Returns Ip address
 *---------------------------------------------------------------------*/

int sr_check_self(struct sr_instance* sr, uint32_t destip)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    /*assert(name);*/
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(if_walker->ip == destip)
        { return 1; }
        if_walker = if_walker->next;
    }

    return 0;
} /* end of method */
/* 
*nl_HandleIcmpPacket(uint8_t* icmpPacket, unsigned int icmpPacketlen)
*{
*	
*	struct icmp* srcIcmp;
*	
*	
*	srcIp = (struct icmp*) icmpPacket;
*	
*	
*	if(checkSum((uint16_t*)icmpPacket, sizeof(struct ip)) == 0)
*	{
*		printf("INFO : Dropping Packet for wrong checksum in ICMP");
*		return NULL;
*	}
*	
*	
*	icmpPacket->icmp_code = 0x0;
*	icmpPacket->icmp_type = 0x0;
*	
*	
*	srcIcmp->icmp_sum = 0x0;
*	srcIcmp->icmp_sum = computeCheckSum((uint16_t*)icmpPacket, sizeof(struct icmp));
*
*}
*/
 
 /*--------------------------------------------------------------------- 
 * Method: nl_handleIPv4Packet
 * Scope: Local
 * Layer: Network Layer
 * 
 * Handles all IPv4 packets that are recieved by this router.
 *---------------------------------------------------------------------*/
struct packet_details* nl_handleIPv4Packet(struct sr_instance* sr, 
		uint8_t *ipPacket/* lent */,
        unsigned int ipPacketLen, char* interface/* lent */)
{
	/* Declaration */
	struct ip* srcIp;
	struct packet_details* packDets; 
	struct sr_if* inSrif;
	struct in_addr tempAddr;
	struct icmp* srcIcmp;
	struct icmp_time_exceeded* icmpTime;
	uint64_t tempData;
	uint32_t testSum;
	packDets = malloc(sizeof(struct packet_details));
	
	/* getting IP Packet */
	srcIp = (struct ip*) ipPacket;

	/* checking ip checksum */
	testSum = srcIp->ip_sum;
	srcIp->ip_sum = 0x00;
	if(verifyCheckSum((uint8_t*)ipPacket, sizeof(struct ip), testSum) == 0)
	{
		printf("\nINFO : Dropping Packet for wrong checksum in IP");
		return NULL;
	}
	
	/* checking ip ttl */
	if((srcIp->ip_ttl == 0x0) || (sr_check_self(sr, srcIp->ip_dst.s_addr)==1))
	{
		printf("\nINFO : Dropping Packet  for ttl=0 in IP");
			
		icmpTime = (struct icmp_time_exceeded*)(ipPacket + sizeof(struct ip));
		memcpy(&tempData, icmpTime, sizeof(uint64_t));
		
		/* checking for packets with no icmp*/
		if(srcIp->ip_ttl == 0x00)
		{
			icmpTime->icmp_type = 0x11;
			icmpTime->icmp_code = 0x0;
		}
		
		if(sr_check_self(sr, srcIp->ip_dst.s_addr)==1)
		{
			icmpTime->icmp_type = 0x03;
			icmpTime->icmp_code = 0x03;
			
		}
		
		icmpTime->icmp_unused = 0x0;
		icmpTime->icmp_ip = *srcIp;
		icmpTime->icmp_ipdata = tempData;
		
		/* computing icmp checksum */
		icmpTime->icmp_sum = 0x0;
		icmpTime->icmp_sum = computeCheckSum((uint8_t*)icmpTime, sizeof(struct icmp));
		
		/* setting src and dst address*/
		tempAddr = srcIp->ip_dst;
		srcIp->ip_dst = srcIp->ip_src;
		srcIp->ip_src = tempAddr;
                
                /* Setting ttl field to 256*/
                srcIp->ip_ttl = 0xFF;
		
		/* computing ip checksum */
		srcIp->ip_sum = 0x0;
		srcIp->ip_sum = computeCheckSum((uint8_t*)ipPacket, sizeof(struct ip));
		packDets->packet = ipPacket;	
		packDets->len = sizeof(struct ip) + sizeof(struct icmp_time_exceeded);
		return packDets;
			
		
		
	}
	
	/* checking for icmp ping */
	inSrif = sr_get_interface(sr, interface);
	if(srcIp->ip_p == 0x01 && srcIp->ip_dst.s_addr == inSrif->ip)
	{
	
		srcIcmp = (struct icmp*)(ipPacket + sizeof(struct ip));
	
		/* checking ICMP checksum */
		testSum = srcIcmp->icmp_sum;
		srcIcmp->icmp_sum = 0x00;
		if(verifyCheckSum((uint8_t*)srcIcmp, sizeof(struct icmp), testSum) == 0)
		{
			printf("\nINFO : Dropping Packet for wrong checksum in ICMP");
			return NULL;
		}
	
		/* setting icmp type,code, identifier, */
		srcIcmp->icmp_code = 0x0;
		srcIcmp->icmp_type = 0x0;
	
		/* computing icmp checksum */
		srcIcmp->icmp_sum = 0x0;
		srcIcmp->icmp_sum = computeCheckSum((uint8_t*)srcIcmp, sizeof(struct icmp));
		
		/* setting src and dst address*/
		tempAddr = srcIp->ip_dst;
		srcIp->ip_dst = srcIp->ip_src;
		srcIp->ip_src = tempAddr;
                
                /* Setting ttl field to 256*/
                srcIp->ip_ttl = 0xFF;
		
		/* computing ip checksum */
		srcIp->ip_sum = 0x0;
		srcIp->ip_sum = computeCheckSum((uint8_t*)ipPacket, sizeof(struct ip));
	
		packDets->packet = ipPacket;
		packDets->len = ipPacketLen;
	
		return packDets;
		
	}
	
	//All normal Cases
		
	/* computing ip checksum */
	srcIp->ip_sum = 0x0;
	srcIp->ip_sum = computeCheckSum((uint16_t*)ipPacket, sizeof(struct ip));
	
	/* setting ip packet*/
	srcIp->ip_ttl = srcIp->ip_ttl - 0x01; 
	
	packDets->packet = ipPacket;
	packDets->len = ipPacketLen;
	
	return packDets;
}

 
 /*--------------------------------------------------------------------- 
 * Method: getGatewayBasedOnDestinationIP
 * Scope: Local
 * Layer: Utility Function for ROUTING TABLE
 * 
 * Returns both Gateway IP and Ethernet Interface for the given destination IP address. 
 * Fetches this information from the ROUTING TABLE.
 *---------------------------------------------------------------------*/
void getGatewayBasedOnDestinationIP(struct sr_instance* sr, struct in_addr destIP, struct in_addr* retGatewayIPAddr, char* retRoutingInterface) {
	struct sr_rt* tempRTptr = sr->routing_table;
	while(tempRTptr != NULL) {
		if(tempRTptr->dest.s_addr == 0) {	// TODO: Check if this works. Use Default Gateway if no other destination IP matches.
			*retGatewayIPAddr = tempRTptr->gw;
			strncpy(retRoutingInterface, tempRTptr->interface, sr_IFACE_NAMELEN);
		}
		if(tempRTptr->dest.s_addr == destIP.s_addr) {
			*retGatewayIPAddr = tempRTptr->gw;
			strncpy(retRoutingInterface, tempRTptr->interface, sr_IFACE_NAMELEN);
			break;
		}
		tempRTptr = tempRTptr->next;
	}
}

time_t getCurrentTimeInSeconds() {
	time_t current;
	time(&current);
	return current;
}

 /*--------------------------------------------------------------------- 
 * Method: removeArpEntry
 * Scope: Local
 * Layer: Utility Function for ARP CACHE
 *  
 * Function to remove a node from the Arp Cache linked list
 *---------------------------------------------------------------------*/
void removeArpEntry(struct arp_cache* nodeToBeRemoved, struct arp_cache* prevNode) {
	if(nodeToBeRemoved == prevNode) {
		// First node in the linked list
		_arpCache = nodeToBeRemoved->next;
	} else {
		prevNode->next = nodeToBeRemoved->next;
	}
	free(nodeToBeRemoved);
}

 /*--------------------------------------------------------------------- 
 * Method: getMACAddressFromARPCache
 * Scope: Local
 * Layer: Utility Function for ARP CACHE
 *  
 * Fetches MAC value of a given IP from the ARP cache. If not found, returns silently.
 *---------------------------------------------------------------------*/
void getMACAddressFromARPCache(uint32_t ipAddr, unsigned char* retMacAddr) {
	struct arp_cache* arpCachePtr = _arpCache;
	struct arp_cache* prevArpCachePtr = arpCachePtr;
	while(arpCachePtr != NULL) {
		if(arpCachePtr->ip == ipAddr) {
			// Check if this is a stale value and remove if it is so.
			if(difftime(getCurrentTimeInSeconds(), arpCachePtr->creationTime) > ARP_CACHE_ENTRY_TIMEOUT) {
				// remove this entry from the ARP cache
				removeArpEntry(arpCachePtr, prevArpCachePtr);
			} else {
				retMacAddr = arpCachePtr->mac;
			}
		}
		prevArpCachePtr = arpCachePtr;
		arpCachePtr = arpCachePtr->next;
	}
}

/*--------------------------------------------------------------------- 
 * Method: dl_constructARP(  struct sr_instance* sr, struct in_addr ip)
 * Scope: Local
 * Layer: Datalink Layer
 * 
 * This method is called when the ARP resolution has to be done. The 
 * destination IP, the receiving interface are passed in as parameters. 
 * Packet returned is complete with the ethernet headers and arp headers.
 *---------------------------------------------------------------------*/
struct packet_details* dl_constructARP(struct sr_instance* sr, struct in_addr ip, char* routingInterface){
	struct sr_ethernet_hdr *eth = (struct sr_ethernet_hdr *)malloc(sizeof(struct sr_ethernet_hdr));
	struct sr_arphdr *arp = (struct sr_arphdr *)malloc(sizeof(struct sr_arphdr));
	struct sr_if* interfaceStructure = sr_get_interface(sr, routingInterface); // Obtain all the details about this interface(IP, MAC etc)
	
	// Set values for Ethernet headers
	for (int i=0;i<ETHER_ADDR_LEN;i++){ 						//48.bit: Ethernet address of destination
		eth->ether_dhost[i]=0xFF;
	} 
	memcpy(eth->ether_shost, interfaceStructure->addr, ETHER_ADDR_LEN);
	eth->ether_type=htons(ETHERTYPE_ARP); 				// 16.bit: Protocol type
	
	// Set values in ARP Packet
	arp->ar_hrd=htons(ARPHDR_ETHER); 					//16.bit: (ar$hrd) Hardware address space
	arp->ar_pro=htons(ETHERTYPE_IP); 					//16.bit: (ar$pro) Protocol address space.  
	arp->ar_hln=ETHER_ADDR_LEN; 				// 8.bit: (ar$hln) byte length of each hardware address
	arp->ar_pln=0x04; 							// TODO: Hardcoded for now. 8.bit: (ar$pln) byte length of each protocol address
	arp->ar_op=htons(ARP_REQUEST);	 					// 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
	memcpy(arp->ar_sha, interfaceStructure->addr, ETHER_ADDR_LEN); // Source Hardware Address
	arp->ar_sip = interfaceStructure->ip;					// Source IP Address
	for (int i=0;i<ETHER_ADDR_LEN;i++){ 					// nbytes: (ar$tha) Hardware address of target of this packet (if known).
		arp->ar_tha[i]=0xFF;
	} 
	arp->ar_tip=ip.s_addr; 							// mbytes: (ar$tpa) Protocol address of target.
	
	// Construct a packet buffer = EthernetHeader + ArpHeader
	struct packet_details *retPacketDetails = (struct packet_details *)malloc(sizeof(struct packet_details));
	retPacketDetails->len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
	retPacketDetails->packet = (uint8_t *)malloc(retPacketDetails->len);
	memcpy(retPacketDetails->packet, eth, sizeof(struct sr_ethernet_hdr)); // Ethernet Header
	memcpy(retPacketDetails->packet+sizeof(struct sr_ethernet_hdr), arp, sizeof(struct sr_arphdr)); // ARP Header
	strncpy(retPacketDetails->interface, routingInterface, sr_IFACE_NAMELEN);
	
	// Free all the memory allocations not required further
	free(eth);
	free(arp);
	
	return retPacketDetails;
}
/*--------------------------------------------------------------------- 
 * Method: addToPacketBuffer
 * Scope: Local
 * Layer: Utility function for PACKET BUFFER
 * 
 * Adds the given IP Packet and corresponding ARP Request Packet to the Packet Buffer
 *---------------------------------------------------------------------*/
void addToPacketBuffer(struct packet_details* arpPacketDetails, 
								struct packet_details* ipPacketDetails, uint32_t gatewayIPAddr) 
{
	// Prepare the buffer node to be added
	struct arp_req_details* node = (struct arp_req_details*)malloc(sizeof(struct arp_req_details));
	node->lastARPRequestSent = getCurrentTimeInSeconds();
	node->ipPacketDetails = ipPacketDetails;
	node->arpRequestPacketDetails = arpPacketDetails;
	node->arpReqCounter = 1;
	node->next = NULL;
	
	struct packet_buffer* ipBufPtr = _pBuf;
	struct packet_buffer* prevIpBufPtr = ipBufPtr;
	
	while(ipBufPtr != NULL) {
		if(ipBufPtr->destIp == gatewayIPAddr) {
			if(ipBufPtr->packetListHead == NULL) {
				// If there are no elements in this IP's buffer
				ipBufPtr->packetListHead = node;
			} else {
				// Add this node to the end
				struct arp_req_details* bufPtr = ipBufPtr->packetListHead;
				while(bufPtr->next!=NULL) {
					bufPtr = bufPtr->next;
				}
				bufPtr->next = node;
			}
			break; // Very very IMPORTANT
		}
		prevIpBufPtr = ipBufPtr;
		ipBufPtr = ipBufPtr->next;
	}
	if(ipBufPtr == NULL) {
		// When no such buffer is found for this IP
		struct packet_buffer* ipBuf = (struct packet_buffer*)malloc(sizeof(struct packet_buffer));
		ipBuf->destIp = gatewayIPAddr;
		ipBuf->packetListHead = node;
		ipBuf->next = NULL;
		
		if(_pBuf == NULL) {
			// This is the first entry being added to the IP Packet Buffer
			_pBuf = ipBuf;
		} else {
			// Append at the end of the IP list then
			prevIpBufPtr->next = ipBuf;
		}
	}
}
 
 /*--------------------------------------------------------------------- 
 * Method: dl_constructEthernetHeader
 * Scope: Local
 * Layer: DataLink Layer
 * 
 * Constructs Ethernet header if MAC value(not stale) is present in ARP Cache. If not present, then sends ARPRequest and returns NULL.
 * Note that this function will also return appropriate interface in "packet_details" object.
 *---------------------------------------------------------------------*/
struct packet_details* dl_constructEthernetPacket(struct sr_instance* sr, 
												struct packet_details *ipPacket)
{
	// 1. From the routing table determine which gateway & eth interface should be used to send the packet
	struct ip* ipHdr = (struct ip*)ipPacket->packet;
	struct sr_ethernet_hdr* ethHdr = NULL;
	struct in_addr gatewayIPAddr;
	char routingInterface[sr_IFACE_NAMELEN];
	getGatewayBasedOnDestinationIP(sr, ipHdr->ip_dst, &gatewayIPAddr, routingInterface);
	// 2. Now check if the gateway's IP is present in the ARP cache.
	unsigned char macAddr[ETHER_ADDR_LEN] = "EMPTY";
	getMACAddressFromARPCache(gatewayIPAddr.s_addr, macAddr);
	if(strncmp((char*)macAddr, "EMPTY", ETHER_ADDR_LEN) == 0) {
		// 3.Case#1: MAC address was not found in ARP cache. So send ARP Request, add all the details to the packet buffer.
		// 3.C1.1 Send ARP request
		struct packet_details* arpPacketDetails = dl_constructARP(sr, gatewayIPAddr, routingInterface);
		sr_send_packet(sr, arpPacketDetails->packet, arpPacketDetails->len, arpPacketDetails->interface);
                printf("\n Sending ARP Request\n");
                z_printARPpacket(arpPacketDetails->packet, arpPacketDetails->len);
		// 3.C1.2 Add the corresponding packet into the buffer
		addToPacketBuffer(arpPacketDetails, ipPacket, gatewayIPAddr.s_addr); 
		// 3.C1.3 Return NULL
		return NULL;
	} else {
		// 3.Case#2: Happy scenario - MAC was found in ARP cache.
		struct sr_ethernet_hdr tempEthHdr;
		ethHdr = &tempEthHdr;
		// NOTE: Here we need to use memcpy instead of strncpy because the data type for MAC addresses is different in "sr_if" and EthernetHeader structures
		memcpy(ethHdr->ether_dhost, macAddr, ETHER_ADDR_LEN);
		memcpy(ethHdr->ether_shost, sr_get_interface(sr, routingInterface)->addr, ETHER_ADDR_LEN);
		ethHdr->ether_type = htons(ETHERTYPE_IP); // TODO: For now, assume that only Network Layer will call this function!
	}
	
	// 4. Ethernet packet = Ethernet Header + IP Packet
	unsigned int retPacketLen = sizeof(struct sr_ethernet_hdr) + ipPacket->len;
	uint8_t* retPacket = (uint8_t*)malloc(retPacketLen);
	memcpy(retPacket, ethHdr, sizeof(struct sr_ethernet_hdr));
	memcpy(retPacket + sizeof(struct sr_ethernet_hdr), ipPacket->packet, ipPacket->len);
	
	struct packet_details *fullPacketDetails = (struct packet_details*)malloc(sizeof(struct packet_details));
	fullPacketDetails->packet = retPacket;
	fullPacketDetails->len = retPacketLen;
	strncpy(fullPacketDetails->interface, routingInterface, sr_IFACE_NAMELEN);
	return fullPacketDetails;  
}

/*--------------------------------------------------------------------- 
 * Method: dl_handlePacket
 * Scope: Local
 * Layer: DataLink Layer
 * 
 * This method is responsible for handling packets with Ethernet layer header.
 *
 *---------------------------------------------------------------------*/
 
void dl_handlePacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
	// Look at ether_type in the packet's Ethernet header
	// Call appropriate layer's functions
	struct sr_ethernet_hdr *ethHdr = (struct sr_ethernet_hdr *)packet;
	struct packet_details *arpPacket;
	struct packet_details *ipPacket;
	int type = -1;
	if(ethHdr->ether_type == htons(ETHERTYPE_ARP)) {
		type = 0;
	} else if(ethHdr->ether_type == htons(ETHERTYPE_IP)) {
		type = 1;
	}
	switch(type) {
		case 0:
			// Pass the Ethernet header and the data part of the packet to the ARP Protocol implementor
			arpPacket = dl_handleARPPacket(sr, packet, len, interface);
			if(arpPacket == NULL) {
				// No job to do as the packet may not be for this router OR this may be a ARP response.
				printf("\n dl_handleARPPacket returned NULL\n");
			} else {
				// Send this packet over the interface same as that of the one from which the router recieved this (interface variable)
				uint8_t* packetToBeSent = arpPacket->packet;
				unsigned int packetToBeSentLen = arpPacket->len;
				
				// Free all the objects
				free(arpPacket);
				
				sr_send_packet(sr, packetToBeSent, packetToBeSentLen, interface);
				printf("\n Sending ARP Response \n");
				z_printARPpacket(packetToBeSent, packetToBeSentLen);
			}
			break;
		case 1:
			// Do not send the Ethernet header to IP layer. Chop the Ethernet header and send the rest over data.
			ipPacket = nl_handleIPv4Packet(sr, packet+sizeof(struct sr_ethernet_hdr), 
													len-sizeof(struct sr_ethernet_hdr), interface);
			if(ipPacket != NULL) {
				// construct the Ethernet header here
				struct packet_details* fullPacket = dl_constructEthernetPacket(sr, ipPacket);
				if(fullPacket == NULL) {
					// This means that the ARP resolution was initiated. Hence do not do anything here.
				} else {
					// Call send data with packet = ethHdr + retPacket->packet
					uint8_t* packetToBeSent = fullPacket->packet;
					unsigned int packetToBeSentLen = fullPacket->len;
					char* interfaceToBeSentOn = fullPacket->interface;
					
					// Free all the objects
					free(ipPacket->packet);
					free(ipPacket);
					free(fullPacket);
					
					// Send this constructed packet
					sr_send_packet(sr, packetToBeSent, packetToBeSentLen, interfaceToBeSentOn);
				}
			}
			break;
	}
}


/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    
    struct sr_ethernet_hdr* ethHdr = (struct sr_ethernet_hdr*)packet;
	if(ethHdr->ether_type == htons(ETHERTYPE_ARP)) {
		printf("\nETHERTYPE_ARP recieved\n");
	} else if(ethHdr->ether_type == htons(ETHERTYPE_IP)) {
		printf("\nETHERTYPE_IP recieved\n");
	} else {
		printf("\nSomething else recieved~!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	}
    
    
    dl_handlePacket(sr, packet, len, interface);
	
	// Once the current packet is handled, check if there are any ARP-Requests in the PacketBuffer must be resent.
	// If there are any such ones, then send and increment the counter. 
	// Also remove the nodes whose count has reached 5 and timeout of the last ARP request has occured.
	struct packet_buffer* ipBufPtr = _pBuf;
	while(ipBufPtr != NULL) {
		struct arp_req_details* bufPtr = ipBufPtr->packetListHead;
		while(bufPtr != NULL) {
			if(difftime(getCurrentTimeInSeconds(),bufPtr->lastARPRequestSent)  >  ARP_REQUEST_TIMEOUT) {
				if(bufPtr->arpReqCounter == 5) {
					printf("\nDropping an IP packet because there was no response for the corresponding ARP Request\n");
				} else {
					// resend the ARP request packet
					sr_send_packet(sr, bufPtr->arpRequestPacketDetails->packet, 
										bufPtr->arpRequestPacketDetails->len, bufPtr->arpRequestPacketDetails->interface);
					bufPtr->arpReqCounter = bufPtr->arpReqCounter+1;
					bufPtr->lastARPRequestSent = getCurrentTimeInSeconds();
				}
			}
			bufPtr = bufPtr->next;
		}
		ipBufPtr = ipBufPtr->next;
	}
	
}/* end sr_ForwardPacket */
/*---------------------------------------------------------------------
 * Method: void z_printARPpacket(uint8_t * packet, unsigned int len)
 *
 * Print an ARP packet
 *---------------------------------------------------------------------*/
void z_printARPpacket(uint8_t * packet, int len) {
	printf("======== ARP packet ========\n");

	/* ARP packet format
	 *  http://tools.ietf.org/html/rfc826
	 Ethernet transmission layer (not necessarily accessible to
	 the user):
	 48.bit: Ethernet address of destination
	 48.bit: Ethernet address of sender
	 16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
	 Ethernet packet data:
	 16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
	 Packet Radio Net.)
	 16.bit: (ar$pro) Protocol address space.  For Ethernet
	 hardware, this is from the set of type
	 fields ether_typ$<protocol>.
	 8.bit: (ar$hln) byte length of each hardware address
	 8.bit: (ar$pln) byte length of each protocol address
	 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
	 nbytes: (ar$sha) Hardware address of sender of this
	 packet, n from the ar$hln field.
	 mbytes: (ar$spa) Protocol address of sender of this
	 packet, m from the ar$pln field.
	 nbytes: (ar$tha) Hardware address of target of this
	 packet (if known).
	 mbytes: (ar$tpa) Protocol address of target.
	 */

	//48.bit: Ethernet address of destination
	printf("Ethernet DST: ");
	for (int i = 0; i < 6; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// 48.bit: Ethernet address of sender
	printf("Ethernet SRC: ");
	for (int i = 6; i < 12; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// 16.bit: Protocol type
	printf("Protocal Type: ");
	for (int i = 12; i < 14; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	//16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
	//                 Packet Radio Net.)
	printf("Hardware address space: ");
	for (int i = 14; i < 16; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	//16.bit: (ar$pro) Protocol address space.  For Ethernet
	//                 hardware, this is from the set of type
	//                 fields ether_typ$<protocol>.
	printf("IP address space: ");
	for (int i = 16; i < 18; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// 8.bit: (ar$hln) byte length of each hardware address
	printf("byte length of each hardware address: ");
	for (int i = 18; i < 19; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// 8.bit: (ar$pln) byte length of each protocol address
	printf("byte length of each IP address: ");
	for (int i = 19; i < 20; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
	printf("opcode (ares_op$REQUEST | ares_op$REPLY): ");
	for (int i = 20; i < 22; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// nbytes: (ar$sha) Hardware address of sender of this
	//                 packet, n from the ar$hln field.
	int arhln = 6; //TODO
	printf("Hardware address of sender of this packet: ");
	for (int i = 22; i < 22 + arhln; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// mbytes: (ar$spa) Protocol address of sender of this
	//                 packet, m from the ar$pln field.
	int arpln = 4; //TODO
	printf("IP address of sender of this packet: ");
	for (int i = 22 + arhln; i < 22 + arhln + arpln; i++) {
		printf("%02X ", packet[i]);
	}
	printf("(");
	for (int i = 22 + arhln; i < 22 + arhln + arpln; i++) {
		printf("%d.", packet[i]);
	}
	printf(")");
	printf("\n");

	// nbytes: (ar$tha) Hardware address of target of this
	//                 packet (if known).
	printf("Hardware address of target of this packet: ");
	for (int i = 22 + arhln + arpln; i < 22 + 2 * arhln + arpln; i++) {
		printf("%02X ", packet[i]);
	}
	printf("\n");

	// mbytes: (ar$tpa) Protocol address of target.
	printf("IP address of target of this packet: ");
	for (int i = 22 + 2 * arhln + arpln; i < 22 + 2* arhln + 2* arpln; i++) {
		printf("%02X ", packet[i]);
	}
	printf("(");
	for (int i = 22 + 2 * arhln + arpln; i < 22 + 2* arhln + 2* arpln; i++) {
		printf("%d.", packet[i]);
	}
	printf(")");
	printf("%d", 22 + 2* arhln + 2* arpln);
	printf("\n");

	printf("========  end  ========\n");
	
}
