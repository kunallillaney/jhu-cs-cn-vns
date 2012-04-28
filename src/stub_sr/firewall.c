/*-----------------------------------------------------------------------------
 * file:  firewall.c
 *
 * Description:
 *
 * Data structures and methods for handling firewall
 *
 *---------------------------------------------------------------------------*/

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

/*--------------------------------------------------------------------- 
 * Method: construct_tuple
 * Scope: Global
 *
 Construct tuple from packet
 *
 *---------------------------------------------------------------------*/

void construct_tuple(tuple* tr, uint8_t* packet)
{
    
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
    
}/* end of check_exception */

/*--------------------------------------------------------------------- 
 * Method: populate_rule_table
 * Scope: Global
 * 
 * Populate rule table
 *
 *---------------------------------------------------------------------*/

struct tuple* populate_rule_table()
{
    
}/* end of populate_rule_table */
