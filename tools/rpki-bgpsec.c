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

int main(int argc, char *argv[])
{
	/* check for the one and only required parameter, the input filename */
	if (argc < 2) {
		printf("Usage: %s [filename]\n", argv[0]);
		return EXIT_FAILURE;
	}
}
