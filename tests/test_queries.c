/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "rtrlib/rtrlib.h"

#define RPKI_LOCAL_CACHE_HOST "localhost"
#define RPKI_LOCAL_CACHE_PORT "0"

// TODO: check which enums from /rtrlib/rtr/packets.c
// are need.

/*
 * The local cache should contain only minimal
 * ROAs, if any at all. It's only purpose is
 * to recieve Queries and send PDUs.
 * 
 */

/*
 This test creates a connection to a local cache.
 This cache sends queries that are rarely sent.
 Examples are:
 * Reset Query
 * Serial Query
 * EOD_PDU with new Interval values

 It should be tested, whether RTRlib reacts to
 these queries the way it should.

 This works in the other direction aswell. If the
 RTRlib sends a query, what should be the expected
 response? Does the expectation meet the actual
 response?
*/

// TODO: sending a query itself is a useless test. Interesting
// is the response (if there is one). Are the queries created
// and sent correctly?

// Send and receive a Serial Query
int test_send_serial_query(struct rtr_socket *rtr_socket)
{
    // Create a Serial Query and send it to the cache.
}

// Send and receive a Reset Query
int test_send_reset_query(struct rtr_socket *rtr_socket)
{
    // Create a Reset Query and send it to the cache.
}

// Check and apply intervals sent from the cache.
int test_received_intervals(struct rtr_socket *rtr_socket)
{
    // Check the intervals from an EOD_PDU.
    // If the values are in bounds, apply them to the socket.
}

int main(void)
{
    // Open a connection to a local cache and call test
    // functions here.
}
