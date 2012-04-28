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
 * Method: construct_tuple
 * Scope: Global
 *
 Construct tuple from packet
 *
 *---------------------------------------------------------------------*/

void construct_tuple(tuple* tr, uint8_t* packet)
{
    struct ip* ip_packet = packet;
    tr->src_ip = ip_packet->ip_src;
    tr->dst_ip = ip_packet->ip_dst;
    tr->protocol = ip_packet->ip_p;
    struct transport_layer transport_packet = packet + sizeof(struct ip);
    tr->src_port = transport_packet->src_port;
    tr->dst_port = transport_packet->dst_port;
    
}/* end of construct_tuple */

/*--------------------------------------------------------------------- 
 * Method: add_entry
 * Scope: Global
 * Add entry in Flow Table
 *
 *---------------------------------------------------------------------*/

void add_entry(struct tuple* tr)
{
    
}/* end of add_entry */

/*--------------------------------------------------------------------- 
 * Method: check_entry
 * Scope: Global
 * 
 * Check if current entry exists or not
 *
 *---------------------------------------------------------------------*/

int check_entry(struct tuple* tr)
{
    struct flow_table flow_table_walker = firewall_instance->head_flow_table;
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
    
}/* end of clear_flow_table*/

/*--------------------------------------------------------------------- 
 * Method: connection_refused
 * Scope: Global
 * 
 * Sends ICMP connection refused packet
 *
 *---------------------------------------------------------------------*/

void connection_refused(struct tuple* tr, uint8_t* packet, unsigned ipLen)
{
    struct firewall* fire;
    if(fire->flow_table_count>=FLOW_TABLE_SIZE){
        clear_flow_table();
        if(fire->flow_table_count<FLOW_TABLE_SIZE) {
            add_entry(tr);
        }
    }
    else if(fire->flow_table_count>=FLOW_TABLE_SIZE) {
        /////send the packet to flow
    }
}/* end of connection_refused*/

/*--------------------------------------------------------------------- 
 * Method: check_exception
 * Scope: Global
 * 
 * Checks if a particular exception exists in the table
 *
 *---------------------------------------------------------------------*/

int check_exception(struct tuple* tr)
{
    struct rule_table rule_table_walker = firewall_instance->head_rule_table;
    struct rule_table *rule_table_walker = (struct rule_table *)malloc(sizeof(struct rule_table));
    while(rule_table_walker->next)
    {
        if((rule_table_walker->ruleEntry->dst_ip.s_addr==tr->dst_ip.s_addr) && (rule_table_walker->ruleEntry->src_ip.s_addr==tr->src_ip.s_addr)
                && (rule_table_walker->ruleEntry->protocol==tr->protocol)){
            if(tr->protocol!=0x6 && tr->protocol!=0x17){
                return 1;
            }
        else {
             if((rule_table_walker->ruleEntry->dst_port!=tr->dst_port)||(rule_table_walker->ruleEntry->src_port!=tr->src_port)){
                return 1;
                }
             }
        }
       else return 0;
     }
   }   
           
} /* end of check_exception */

/*--------------------------------------------------------------------- 
 * Method: populate_rule_table
 * Scope: Global
 * 
 * Populate rule table
 *
 *---------------------------------------------------------------------*/

struct tuple* populate_rule_table()
{
FILE* file = fopen("rule_table", "r");
char linebuffer[40]; //a little extra room here than needed
struct tuple ip;
int i = 0, l = 0;

while(fgets(linebuffer, 40, file)){
    fgets(linebuffer, 40, file);
    strcpy(ip.src_ip.s_addr, linebuffer);

    l = strlen(linebuffer);
    for(i = 0; i < l; ++i){
        if(linebuffer[i] == '\n'){
            linebuffer[i] = '\0';
            break;
        }
    }

    fgets(linebuffer, 40, file);
    strcpy(ip.dst_ip.s_addr, linebuffer);

    l = strlen(linebuffer);
    for(i = 0; i < l; ++i){
        if(linebuffer[i] == '\n'){
            linebuffer[i] = '\0';
            break;
        }
    }

    fgets(linebuffer, 40, file);
    ip.protocol=linebuffer;

    fgets(linebuffer, 40, file);
    ip.src_port = atoi(linebuffer);
    fgets(linebuffer, 40, file);
    ip.dst_port = atoi(linebuffer);
    }
return ip;    
}/* end of populate_rule_table */

/*--------------------------------------------------------------------- 
 * Method: check_interface
 * Scope: Global
 * 
 * Check for the interface. If external, then return true.
 *
 *---------------------------------------------------------------------*/

void check_interface(struct sr_instance *sr,struct in_addr ip_addr)
{
    char * shost_chr=get_hardware_address(struct sr_instance* sr, struct in_addr ip_addr);
    if((memcmp(shost_chr,ETH0,ETHER_ADDR_LEN)==1)){/////////////////add macro
        return 1;
    }
    else 
        return 0;
}/* end of check_interface*/


char *get_hardware_address(struct sr_instance* sr, struct in_addr ip_addr)
{
        char *hrd_addr;
        hrd_addr = (char *)malloc(sr_IFACE_NAMELEN*sizeof(char));
        struct sr_rt *rt_walker = sr->routing_table;
        while(rt_walker->next)
        {
                if(ip_addr.s_addr == (rt_walker->dest).s_addr)
                {
                        int i;
                        for(i = 0; i < sr_IFACE_NAMELEN; i++)
                        {
                                *(hrd_addr + i) = rt_walker->interface[i];
                        }
                }
                rt_walker = rt_walker->next;
        }
        return hrd_addr;
}
