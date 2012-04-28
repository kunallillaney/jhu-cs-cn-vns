/* 
 * File:   firewall.h
 * Author: user
 *
 * Created on April 28, 2012, 4:49 AM
 * Contains structs of flowtable, ruletable,tuple
 */
#ifndef sr_FIREWALL_H
#define sr_FIREWALL_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#ifndef FLOW_TABLE_SIZE
#define FLOW_TABLE_SIZE 64
#endif

#ifndef FIREWALL_ENABLED
#define FIREWALL_ENABLED 1
#endif

#ifndef INIT
#define INIT 1
#endif

struct firewall* firewall_instance;

struct tuple
{
    struct in_addr src_ip;     //Source Address
    struct in_addr dst_ip;     //Destination Address
    uint8_t protocol;   //Protocol
    uint16_t src_port;       // Source Port
    uint16_t dst_port;       // Destination Port 
};

//Methods for tuple
void construct_tuple(struct tuple* tr, uint8_t* packet);        // Construct tuple from packet
struct tuple* invert_tuple(struct tuple* tr);   // Invert tuple

struct flow_table
{
    struct tuple* flowEntry;     //Flow Entry
    int ttl;                    //Time to live 
    time_t timeStamp;           //TimeStamp when stored
    struct flow_table* next;         //Points to the next entry in the table 
};
//Methods for flow_table
struct packet_details* add_entry(uint8_t* packet, unsigned ipLen);     //Add entry in Flow Table
int check_entry(struct tuple* tr);      //Check if current entry exists or not
void clear_flow_table();                //Clear Flow table of expired values
void increment_entry(struct tuple* tr); //Increment entry ttl by X
void add_tuple(struct tuple* tr);       //Add 2tuples in flow_table
struct packet_details* send_icmp_refused(uint8_t* packet, unsigned ipLen); //Sends ICMP packet refused;

struct rule_table
{
    struct tuple* ruleEntry;     //Rule entry exception
    struct rule_table* next;     //Points to the next entry in the table
};

//Methods for rule_table
int check_exception(struct tuple* tr); //Checks if a particular exception exists in the table

struct firewall
{
    struct flow_table* head_flow_table;
    struct rule_table* head_rule_table;
    int flow_table_count; 
};

//Methods for firewall
struct rule_table* populate_rule_table(); //Populate rule table
struct packet_details* intiate_firewall(uint8_t *ipPacket,unsigned int ipPacketLen, char* interface, int* status);
int check_interface(char* interface_name);
void init();
#endif /* --  sr_FIREWALL_H -- */
