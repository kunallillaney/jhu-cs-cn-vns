/*-----------------------------------------------------------------------------
 * file:  firewall.c
 *
 * Description:
 * Data structures and methods for handling firewall
 *
 *---------------------------------------------------------------------------*/
#include <unistd.h>
#include <time.h>

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _DARWIN_
#include <sys/types.h>
#endif /* _DARWIN_ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "firewall.h"
#include "sr_protocol.h"
/*--------------------------------------------------------------------- 
 * Method: computeCheckSum
 * Scope: Local
 * Layer: Network Layer
 * 
 * Calculates the checksum for a given packet.
 *---------------------------------------------------------------------*/

uint16_t computeCheckSum(uint8_t *buff, uint16_t len_header);

/*--------------------------------------------------------------------- 
 * Method: checkSum
 * Scope: Local
 * Layer: Network Layer
 * 
 * Verifys the checksum for a given packet.
 *---------------------------------------------------------------------*/

uint16_t verifyCheckSum(uint8_t *buff, uint16_t len_header, uint16_t testSum);

time_t getCurrentTimeInSeconds();

/*--------------------------------------------------------------------- 
 * Method: construct_tuple
 * Scope: Global
 *
 Construct tuple from packet
 *
 *---------------------------------------------------------------------*/

void construct_tuple(struct tuple* tr, uint8_t* packet)
{
    struct ip* ip_packet = (struct ip*)packet;
    tr->src_ip = ip_packet->ip_src;
    tr->dst_ip = ip_packet->ip_dst;
    tr->protocol = ip_packet->ip_p;
    struct transport_layer* transport_packet = (struct transport_layer*)(packet + sizeof(struct ip));
    tr->src_port = transport_packet->src_port;
    tr->dst_port = transport_packet->dst_port;
    
}/* end of construct_tuple */

/*--------------------------------------------------------------------- 
 * Method: add_entry
 * Scope: Global
 * Add entry in Flow Table
 *
 *---------------------------------------------------------------------*/

struct packet_details* add_entry(uint8_t* packet, unsigned ipLen)
{
    struct tuple* tr = (struct tuple*)malloc(sizeof(struct tuple));
    construct_tuple(tr, packet);
    
    if(check_entry(tr)==1)
    {
        increment_entry(tr);
        increment_entry(invert_tuple(tr));
        printf("\n Entry Already Exists and both flows incremented by X \n");
    }
    else if(firewall_instance->flow_table_count> (FLOW_TABLE_SIZE-2))
    {
        clear_flow_table();
        if(firewall_instance->flow_table_count> (FLOW_TABLE_SIZE-2))
        {
           printf("\n  FlOW TABLE FULL RETURNING ICMPreachable\n"); 
           return send_icmp_refused(packet, ipLen);
        }
        else
        {
            add_tuple(tr);
        }
    }
    else
    {
        add_tuple(tr);
    }
    return NULL;
}/* end of add_entry */

/*--------------------------------------------------------------------- 
 * Method: add_tuple
 * Scope: Global
 * add 2 tuples in table
 *
 *---------------------------------------------------------------------*/
void add_tuple(struct tuple* tr)
{
    firewall_instance->flow_table_count += 2;
    time_t current_time = getCurrentTimeInSeconds();
    struct flow_table* flow_table_walker = firewall_instance->head_flow_table;
    struct flow_table* flow_table_entry = (struct flow_table*)malloc(sizeof(struct flow_table));
    flow_table_entry->flowEntry = tr;
    flow_table_entry->next = NULL;
    flow_table_entry->timeStamp = current_time;
    flow_table_entry->ttl = 5;
    
    struct flow_table* inv_flow_table_entry = (struct flow_table*)malloc(sizeof(struct flow_table));
    inv_flow_table_entry->flowEntry = invert_tuple(tr);
    inv_flow_table_entry->next = NULL;
    inv_flow_table_entry->timeStamp = current_time;
    inv_flow_table_entry->ttl = 5;
  
    flow_table_entry->next = inv_flow_table_entry;
    if(flow_table_walker == NULL){
        firewall_instance->head_flow_table = flow_table_entry;
        return;
    }
    else
    {
        while(flow_table_walker->next)
        {
                flow_table_walker = flow_table_walker->next;
        }
    
        flow_table_walker->next = flow_table_entry;
    }
}

struct packet_details* send_icmp_refused(uint8_t* ipPacket, unsigned ipLen)
{
    struct ip* srcIp;
    struct packet_details* packDets; 
    struct in_addr tempAddr;
    struct icmp_time_exceeded* icmpTime;
    uint32_t testSum;
    uint64_t tempData;
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
        icmpTime = (struct icmp_time_exceeded*)(ipPacket + sizeof(struct ip));
	memcpy(&tempData, icmpTime, sizeof(uint64_t));
        
        icmpTime->icmp_type = 0x03;
	icmpTime->icmp_code = 0x03;
			
	icmpTime->icmp_unused = 0x0;
	icmpTime->icmp_ip = *srcIp;
	icmpTime->icmp_ipdata = tempData;
		
	/* computing icmp checksum */
	icmpTime->icmp_sum = 0x0;
	icmpTime->icmp_sum = computeCheckSum((uint8_t*)icmpTime, sizeof(struct icmp_time_exceeded));
		
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

/*--------------------------------------------------------------------- 
 * Method: increment_entry
 * Scope: Global
 * Increment entry in Flow Table by X
 *
 *---------------------------------------------------------------------*/
void increment_entry(struct tuple* tr)
{
    struct flow_table* flow_table_walker = firewall_instance->head_flow_table;
    while(flow_table_walker->next)
    {
        if(memcmp(&(flow_table_walker->flowEntry),tr,sizeof(struct tuple))==0)
        {
            flow_table_walker->ttl += 5;
            return;
        }
         flow_table_walker = flow_table_walker->next;   
    }
}/* end of increment_entry*/


/*--------------------------------------------------------------------- 
 * Method: check_entry
 * Scope: Global
 * 
 * Check if current entry exists or not
 *
 *---------------------------------------------------------------------*/

int check_entry(struct tuple* tr)
{
    struct flow_table* flow_table_walker = firewall_instance->head_flow_table;
    if(flow_table_walker == NULL) {
        return 0;
    }
    while(flow_table_walker->next)
    {
        if(memcmp(&(flow_table_walker->flowEntry),tr,sizeof(struct tuple))==0)
            return 1;
         flow_table_walker = flow_table_walker->next;   
    }
    return 0;
}/* end of check_entry */

/*--------------------------------------------------------------------- 
 * Method: clear_flow_table
 * Scope: Global
 * 
 * Clear Flow table of expired values
 *
 *---------------------------------------------------------------------*/

void clear_flow_table()
{
    struct flow_table* flow_table_walker = firewall_instance->head_flow_table;
    struct flow_table* prev_walker = flow_table_walker;
    
    while(flow_table_walker->next)
    {
        if((getCurrentTimeInSeconds(),flow_table_walker->timeStamp) > flow_table_walker->ttl)
        {
            firewall_instance->flow_table_count -=1;
            prev_walker->next = flow_table_walker->next;
        }
        prev_walker = flow_table_walker;
        flow_table_walker = flow_table_walker->next;   
    }
}/* end of clear_flow_table*/

/*--------------------------------------------------------------------- 
 * Method: invert_tuple
 * Scope: Global
 * 
 * Invert tuple
 *
 *---------------------------------------------------------------------*/

struct tuple* invert_tuple(struct tuple* tr) 
{
    struct tuple* opposite_tuple=(struct tuple*)malloc(sizeof(struct tuple));
    opposite_tuple->src_ip = tr->dst_ip;
    opposite_tuple->dst_ip = tr->src_ip;
    opposite_tuple->src_port = tr->dst_port;
    opposite_tuple->dst_port = tr->src_port;
    opposite_tuple->protocol = opposite_tuple->protocol;
    
    return opposite_tuple;
}/* end of invert_tuple */

/*--------------------------------------------------------------------- 
 * Method: connection_refused
 * Scope: Global
 * 
 * Sends ICMP connection refused packet
 *
 *---------------------------------------------------------------------*/


/*--------------------------------------------------------------------- 
 * Method: check_exception
 * Scope: Global
 * 
 * Checks if a particular exception exists in the table
 *
 *---------------------------------------------------------------------*/

int check_exception(struct tuple* tr)
{
    struct rule_table* rule_table_walker = firewall_instance->head_rule_table;
    while(rule_table_walker)
    {     
        if(
        
        ((rule_table_walker->ruleEntry->dst_ip.s_addr== 0 ) || (rule_table_walker->ruleEntry->dst_ip.s_addr==tr->dst_ip.s_addr)) 
        && 
        ((rule_table_walker->ruleEntry->src_ip.s_addr== 0) || (rule_table_walker->ruleEntry->src_ip.s_addr==tr->src_ip.s_addr))
        && 
        ((rule_table_walker->ruleEntry->protocol== 0) || (rule_table_walker->ruleEntry->protocol==tr->protocol))
        
                )
        {
            if(tr->protocol==0x1)
            {
                return 1;
            } else {
                if (((rule_table_walker->ruleEntry->dst_port== 0 )||(rule_table_walker->ruleEntry->dst_port==tr->dst_port))
                        &&((rule_table_walker->ruleEntry->src_port== 0 )||(rule_table_walker->ruleEntry->src_port==tr->src_port)))
                    return 1;
            }
        }
        rule_table_walker = rule_table_walker->next; 
     }
     return 0;      
} /* end of check_exception */

/*--------------------------------------------------------------------- 
 * Method: populate_rule_table
 * Scope: Global
 * 
 * Populate rule table
 *
 *---------------------------------------------------------------------*/

struct rule_table* populate_rule_table()
{
        //FILE* file = fopen("/home/lfs/NetBeansProjects/trunk/src/stub_sr/rule_table", "r");
        FILE* file = fopen("rule_table", "r");
        if(file == NULL) {
            printf("\nno file rule_table found\n");
            return NULL;
        }
        struct rule_table* prevRuleTableNode = NULL;
        struct rule_table* ruleTableNode = NULL;
        struct rule_table* retTableNode = NULL;
        struct tuple* tempTuple = NULL;
        unsigned int sip1,sip2,sip3,sip4,dip1,dip2,dip3,dip4,protocolInFile;
        long unsigned srcPort,destPort;
        //int n;
	//char s;        
        //long unsigned t;
        //while (fscanf(file,"%c.%d %lu",&s, &n, &t) != EOF) 
        while (fscanf(file,"%u.%u.%u.%u %u.%u.%u.%u %u %lu %lu",&sip1,&sip2,&sip3,&sip4,&dip1,&dip2,&dip3,&dip4,&protocolInFile,&srcPort,&destPort) != EOF) 
	{
            prevRuleTableNode = ruleTableNode;
            tempTuple = (struct tuple*)malloc(sizeof(struct tuple));
            ruleTableNode = (struct rule_table*)malloc(sizeof(struct rule_table));
            ruleTableNode->ruleEntry = tempTuple;
            ruleTableNode->next = NULL;
            
            if(retTableNode == NULL) {
                retTableNode = ruleTableNode;
            } else {
                prevRuleTableNode->next = ruleTableNode;
            }
            
            memcpy(&tempTuple->src_ip, &sip1, sizeof(uint8_t));
            memcpy((uint8_t*)(&tempTuple->src_ip)+1, &sip2, sizeof(uint8_t));
            memcpy((uint8_t*)(&tempTuple->src_ip)+2, &sip3, sizeof(uint8_t));
            memcpy((uint8_t*)(&tempTuple->src_ip)+3, &sip4, sizeof(uint8_t));
            
            memcpy(&tempTuple->dst_ip, &dip1, sizeof(uint8_t));
            memcpy((uint8_t*)(&tempTuple->dst_ip)+1, &dip2, sizeof(uint8_t));
            memcpy((uint8_t*)(&tempTuple->dst_ip)+2, &dip3, sizeof(uint8_t));
            memcpy((uint8_t*)(&tempTuple->dst_ip)+3, &dip4, sizeof(uint8_t));
            
            tempTuple->protocol = protocolInFile;
            tempTuple->src_port = srcPort;
            tempTuple->dst_port = destPort;
        }
        fclose(file);
        return retTableNode;
}/* end of populate_rule_table */

/*--------------------------------------------------------------------- 
 * Method: check_interface
 * Scope: Global
 * 
 * Check for the interface. If external, then return true.
 *
 *---------------------------------------------------------------------*/

int check_interface(char* interface_name)
{
    
    if((strcmp(interface_name,"eth0")==0))
        return 1;
    else
        return 0;
}/* end of check_interface*/

struct packet_details* intiate_firewall(uint8_t *ipPacket,unsigned int ipPacketLen, char* interface, int* status)
{
    if(check_interface(interface)==0){
        return add_entry(ipPacket,ipPacketLen);
    }
    else
    {
        struct tuple* tr = (struct tuple*)malloc(sizeof(struct tuple));
        construct_tuple(tr, ipPacket);
        if(firewall_instance->head_flow_table!=NULL && check_entry(tr)==1)
        {
            increment_entry(tr);
            increment_entry(invert_tuple(tr));
            *status = 0; //0 means do nothing
            return NULL;
        }
        else if(check_exception(tr)==1)
        {
            return add_entry(ipPacket,ipPacketLen);
        }
    }
    *status = 1; //1 means drop packet
    return NULL;
}

void init()
{
    firewall_instance = (struct firewall*)malloc(sizeof(struct firewall));
    firewall_instance->head_rule_table = populate_rule_table();
    firewall_instance->head_flow_table = NULL;
    firewall_instance->flow_table_count = 0;
}
