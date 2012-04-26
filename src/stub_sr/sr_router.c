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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

// Two Global Variables

struct packet_buffer *pBuf = NULL;
struct arp_cache *arpCache = NULL;

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
 * Method: dl_constructEthernetHeader
 * Scope: Local
 * Layer: DataLink Layer
 * 
 * Constructs Ethernet header if MAC value(not stale) is present in ARP Cache. If not present, then sends ARPRequest and returns NULL.
 *---------------------------------------------------------------------*/
struct sr_ethernet_hdr* dl_constructEthernetHeader(struct sr_instance* sr, 
												struct packet_details *packetDetails, char* interface/* lent */)
 {
	 // TODO
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
	struct packet_details *retPacket;
	switch(ethHdr->ether_type) {
		case ETHERTYPE_ARP: 
			// Pass the Ethernet header and the data part of the packet to the ARP Protocol implementor
			retPacket = dl_handleARPPacket(sr, ethHdr, 
									packet+sizeof(struct sr_ethernet_hdr), len-sizeof(struct sr_ethernet_hdr));
			if(retPacket == NULL) {
				// No job to do as the packet may not be for me or this may be a ARP response.
			} else {
				// Send this packet over the interface same as that of the one from which the router recieved this (interface variable)
				sr_send_packet(sr, retPacket->packet, retPacket->len, interface);
			}
			break;
		case ETHERTYPE_IP:
			// Do not send the Ethernet header to IP layer. Chop the Ethernet header and send the rest over data.
			retPacket = nl_handleIPv4Packet(sr, packet+sizeof(struct sr_ethernet_hdr), 
													len-sizeof(struct sr_ethernet_hdr), interface);
			if(retPacket != NULL) {
				// construct the Ethernet header here
				struct sr_ethernet_hdr* ethHdr = dl_constructEthernetHeader(sr, retPacket, interface);
				if(ethHdr == NULL) {
					// This means that the ARP resolution was initiated. Hence do not do anything here.
					// TODO.
				} else {
					// Call send data with packet = ethHdr + retPacket.ipHdr + retPacket.data
					// TODO.
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

}/* end sr_ForwardPacket */
