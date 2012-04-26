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

/*--------------------------------------------------------------------- 
 * Method: dl_handleARPPacket
 * Scope: Local
 * Layer: DataLink Layer
 * 
 * Handles all ARP packets that are recieved by this router.
 *---------------------------------------------------------------------*/
struct packet_details* dl_handleARPPacket(struct sr_instance* sr, struct sr_ethernet_hdr *ethHdr,
        uint8_t *arpHeader/* lent */,
        unsigned int arpHeaderLen) 
{
	// TODO: Check ethHdr->ether_type and perform request and response handling here.
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
void getGatewayBasedOnDestinationIP(struct sr_instance* sr, struct in_addr destIP, uint32_t* retGatewayAddr, char* retRoutingInterface) {
	struct sr_rt* tempRTptr = sr->routing_table;
	while(tempRTptr != NULL) {
		if(tempRTptr->dest.s_addr == 0) {	// TODO: Check if this works. Use Default Gateway if no other destination IP matches.
			*retGatewayAddr = tempRTptr->gw.s_addr;
			retRoutingInterface = tempRTptr->interface;
		}
		if(tempRTptr->dest.s_addr == destIP.s_addr) {
			*retGatewayAddr = tempRTptr->gw.s_addr;
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
			if(difftime(getCurrentTimeInSeconds(), arpCachePtr->creationTime) > ARP_TIMEOUT) {
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
	uint32_t gatewayAddr;
	char routingInterface[sr_IFACE_NAMELEN];
	getGatewayBasedOnDestinationIP(sr, ipHdr->ip_dst, &gatewayAddr, routingInterface);
	// 2. Now check if the gateway's IP is present in the ARP cache.
	unsigned char macAddr[ETHER_ADDR_LEN] = "EMPTY";
	getMACAddressFromARPCache(gatewayAddr, macAddr);
	if(strncmp((char*)macAddr, "EMPTY", ETHER_ADDR_LEN) == 0) {
		// 3.Case#1: MAC address was not found in ARP cache. So send ARP Request, add all the details to the packet buffer.
		// TODO
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
	
	// Now free all the memories allocated
	free(ethHdr);
	
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
			arpPacket = dl_handleARPPacket(sr, ethHdr, 
									packet+sizeof(struct sr_ethernet_hdr), len-sizeof(struct sr_ethernet_hdr));
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
					free(ipPacket);
					free(ipPacket->packet);
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

	// TODO: Once the current packet is handled, check if there are any ARP-Requests in the PacketBuffer must be resent.
	// TODO: If there are any such ones, then send and increment the counter. 
	// TODO: Also remove the nodes whose count has reached 5 and timeout of the last ARP request has occured.
	
}/* end sr_ForwardPacket */
