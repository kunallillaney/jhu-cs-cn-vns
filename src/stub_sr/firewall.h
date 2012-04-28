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

struct tuple
{
    in_addr srcAddr;    //Source Address
    in_addr dstAddr;    //Destination Address
    uint8_t protocol;   //Protocol
    int srcPort;        // Source Port
    int dstPort;        // Destination Port 
};

//Methods for tuple
void construct_tuple(tuple* tr, uint8_t* packet);       // Construct tuple from packet

struct flow_table
{
    struct tuple flowEntry;     //Flow Entry
    int ttl;                    //Time to live 
    time_t timeStamp;           //TimeStamp when stored
    struct flow_table* next;         //Points to the next entry in the table 
};
//Methods for flow_table
void add_entry(struct tuple* tr);       //Add entry in Flow Table
int check_entry(struct tuple* tr);      //Check if current entry exists or not
void clear_flow_table();                //Clear Flow table of expired values
void connection_refused(struct tuple* tr, uint8_t* packet, unsigned ipLen); //Sends ICMP connection refused packet

struct rule_table
{
    struct tuple ruleEntry;     //Rule entry exception
    struct rule_table next;     //Points to the next entry in the table
};

//Methods for rule_table
int check_exception(struct tuple* tr); //Checks if a particular exception exists in the table

struct firewall
{
    #ifndef FLOW_TABLE_SIZE
    #define FLOW_TABLE_SIZE 64
    #endif
    
    struct flow_table* head_flow_table;
    struct rule_table* head_rule_table;
};

//Methods for firewall
struct tuple* populate_rule_table(); //Populate rule table

#endif /* --  sr_FIREWALL_H -- */