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
		strncpy((char*)arpCachePtr->mac, (char*)macAddr, ETHER_ADDR_LEN);
		arpCachePtr->next = NULL;
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
				ethHdr->ether_type = ETHERTYPE_IP; // TODO: For now, assume that only Network Layer packets buffered!
				
				unsigned int fullPacketLen = sizeof(tempEthHdr) + bufPtr->ipPacketDetails->len;
				uint8_t* fullPacket = (uint8_t*)malloc(fullPacketLen);
				memcpy(fullPacket, &tempEthHdr, sizeof(tempEthHdr));
				memcpy(fullPacket+sizeof(tempEthHdr), bufPtr->ipPacketDetails->packet, bufPtr->ipPacketDetails->len);
				
				// We can use the same interface that was used to send the ARP request.
				sr_send_packet(sr, fullPacket, fullPacketLen, bufPtr->arpRequestPacketDetails->interface);
				
				// free all memory
				free(bufPtr->ipPacketDetails->packet);
				free(bufPtr->arpRequestPacketDetails->packet);
				free(fullPacket);
				
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
		switch(a_hdr->ar_op){
			case ARP_REQUEST:
				if ((a_hdr->ar_tip == iface->ip )) {
					memcpy(e_hdr->ether_dhost,e_hdr->ether_shost,ETHER_ADDR_LEN); /* destination ethernet address */
					a_hdr->ar_op=ARP_REPLY;    
					memcpy(a_hdr->ar_tha,a_hdr->ar_sha,ETHER_ADDR_LEN);
					a_hdr->ar_tip=a_hdr->ar_sip;
					memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);// Source Hardware Address
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
			case ARP_REPLY:
				dl_local_handleARPResponse(sr, packet, len, interface);
				break;
		}
	return NULL;
}


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
	// TODO Kunal: Implement all IP Protocols here.
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
			retRoutingInterface = tempRTptr->interface;
		}
		if(tempRTptr->dest.s_addr == destIP.s_addr) {
			*retGatewayIPAddr = tempRTptr->gw;
			retRoutingInterface = tempRTptr->interface;
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
	eth->ether_type=ETHERTYPE_ARP; 				// 16.bit: Protocol type
	
	// Set values in ARP Packet
	arp->ar_hrd=ARPHDR_ETHER; 					//16.bit: (ar$hrd) Hardware address space
	arp->ar_pro=ETHERTYPE_IP; 					//16.bit: (ar$pro) Protocol address space.  
	arp->ar_hln=ETHER_ADDR_LEN; 				// 8.bit: (ar$hln) byte length of each hardware address
	arp->ar_pln=0x04; 							// TODO: Hardcoded for now. 8.bit: (ar$pln) byte length of each protocol address
	arp->ar_op=ARP_REQUEST;	 					// 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
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
	struct ip* ipHdr = (struct ip*)ipPacket;
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
		ethHdr->ether_type = ETHERTYPE_IP; // TODO: For now, assume that only Network Layer will call this function!
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
	switch(ethHdr->ether_type) {
		case ETHERTYPE_ARP: 
			// Pass the Ethernet header and the data part of the packet to the ARP Protocol implementor
			arpPacket = dl_handleARPPacket(sr, packet, len, interface);
			if(arpPacket == NULL) {
				// No job to do as the packet may not be for this router OR this may be a ARP response.
			} else {
				// Send this packet over the interface same as that of the one from which the router recieved this (interface variable)
				uint8_t* packetToBeSent = arpPacket->packet;
				unsigned int packetToBeSentLen = arpPacket->len;
				
				// Free all the objects
				free(arpPacket);
				
				sr_send_packet(sr, packetToBeSent, packetToBeSentLen, interface);
			}
			break;
		case ETHERTYPE_IP:
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
