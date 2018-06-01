/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rtrlib/bgpsec/bgpsec.h"
#include "rtrlib/spki/hashtable/ht-spkitable.h"

#ifdef BGPSEC

static struct spki_record *create_record(int ASN,
					 uint8_t *ski,
					 int spki_offset,
					 struct rtr_socket *socket)
{
	struct spki_record *record = malloc(sizeof(struct spki_record));
	u_int32_t i;

	memset(record, 0, sizeof(*record));
	record->asn = ASN;
	memcpy(record->ski, ski, SKI_SIZE);

	for (i = 0; i < sizeof(record->spki) / sizeof(u_int32_t); i++)
		((u_int32_t *)record->spki)[i] = i + spki_offset;

	record->socket = socket;
	return record;
}

void _print_byte_sequence(unsigned char *bytes,
			  size_t bytes_size,
			  char alignment)
{
	int bytes_printed = 1;
	switch (alignment) {
	case 'h':
		for (int i = 0; i < bytes_size; i++)
			printf("Byte %d/%d: %02x\n", i+1, bytes_size, (uint8_t)bytes[i]);
		break;
	case 'v':
	default:
		for (int i = 0; i < bytes_size; i++, bytes_printed++) {
			printf("%02x ", (uint8_t)bytes[i]);

			// Only print 16 bytes in a single line.
			if (bytes_printed % 16 == 0)
				printf("\n");
		}
		break;
	}
	// TODO: that's ugly.
	// If there was no new line printed at the end of the for loop,
	// print an extra new line.
	if (bytes_size % 16 != 0)
		printf("\n");
	printf("\n");
}

static void init_structs(void)
{
	struct spki_table table;
	struct rtr_socket *socket = malloc(sizeof(struct rtr_socket));

	enum bgpsec_result result;
	int as_hops = 2;

	// AS(64496)--->AS(65536)--->AS(65537)

	uint8_t first_bytes_sequence[] = {
		0x00,0x01,0x00,0x00,	// target as (65536)
		0x01,			// pcount
		0x00,			// flags
		0x00,0x00,0xFB,0xF0,	// asn 64496
		0x01,			// algo id
		0x00,0x01,		// afi
		0x01,			// safi
		0x18,0xC0,0x00,0x02	// prefix 192.0.2.0/24
	};

	uint8_t second_bytes_sequence[] = {
		0x00,0x01,0x00,0x01,	// target as (65537)
		0xAB,0x4D,0x91,0x0F,0x55, // ski (64496)
		0xCA,0xE7,0x1A,0x21,0x5E, //
		0xF3,0xCA,0xFE,0x3A,0xCC, //
		0x45,0xB5,0xEE,0xC1,0x54, //
		0x00,0x48,		// sig len
		0x30,0x46,0x02,0x21,0x00,0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD, // sig
		0x9C,0xD4,0x5E,0x81,0xD6,0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E, //
		0xA8,0x4E,0xAF,0x37,0x16,0x02,0x21,0x00,0x8E,0x21,0xF6,0x0E,0x44,0xC6,0x06,0x6C, //
		0x8B,0x8A,0x95,0xA3,0xC0,0x9D,0x3A,0xD4,0x37,0x95,0x85,0xA2,0xD7,0x28,0xEE,0xAD, //
		0x07,0xA1,0x7E,0xD7,0xAA,0x05,0x5E,0xCA,					 //
		0x01,			// pcount
		0x00,			// flags
		0x00,0x01,0x00,0x00,	// asn 65536
		0x01,			// pcount
		0x00,			// flags
		0x00,0x00,0xFB,0xF0,	// asn 64496
		0x01,			// algo id
		0x00,0x01,		// afi
		0x01,			// safi
		0x18,0xC0,0x00,0x02	// prefix 192.0.2.0/24
	};

	/* The size in bytes of one signature_seg in this test case is:
	 * 10 * 1 (ski) +
	 * 2 (sig_len) +
	 * 5 * 1 (signature)
	 * -----------
	 * 17
	 */
	struct signature_seg *ss[2];

	/* The size in bytes of one secure_path_seg in this test case is:
	 * 1 (pcount) +
	 * 1 (conf_seg) +
	 * 4 (asn)
	 * -----------
	 * 6
	 */
	struct secure_path_seg *sps[2];

	/* The size in bytes of bgpsec_data in this test case is:
	 * 1 (alg_suite_id) +
	 * 2 (afi) +
	 * 1 (safi) +
	 * 2 * 1 (nlri)
	 * -----------
	 * 6
	 */
	struct bgpsec_data *bg = malloc(sizeof(struct bgpsec_data));

	/* In total, the raw data that is processed by the validation
	 * function in this test case is:
	 * 2 * 17 (sig_segs)
	 * 2 * 6 (seg_path_segs)
	 * 6 (bgpsec_data)
	 * -----------
	 * 52
	 */

	uint8_t ski1[]  = {
			 0x47,0xF2,0x3B,0xF1,0xAB,
			 0x2F,0x8A,0x9D,0x26,0x86,
			 0x4E,0xBB,0xD8,0xDF,0x27,
			 0x11,0xC7,0x44,0x06,0xEC
			};

	uint8_t sig1[]  = {
			 0x30,0x46,0x02,0x21,0x00,0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,
			 0x9C,0xD4,0x5E,0x81,0xD6,0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,
			 0xA8,0x4E,0xAF,0x37,0x16,0x02,0x21,0x00,0x90,0xF2,0xC1,0x29,0xAB,0xB2,0xF3,0x9B,
			 0x6A,0x07,0x96,0x3B,0xD5,0x55,0xA8,0x7A,0xB2,0xB7,0x33,0x3B,0x7B,0x91,0xF1,0x66,
			 0x8F,0xD8,0x61,0x8C,0x83,0xFA,0xC3,0xF1
			};

	uint8_t ski2[]  = {
			 0xAB,0x4D,0x91,0x0F,0x55,
			 0xCA,0xE7,0x1A,0x21,0x5E,
			 0xF3,0xCA,0xFE,0x3A,0xCC,
			 0x45,0xB5,0xEE,0xC1,0x54
			};

	uint8_t sig2[]  = {
			 0x30,0x46,0x02,0x21,0x00,0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,
			 0x9C,0xD4,0x5E,0x81,0xD6,0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,
			 0xA8,0x4E,0xAF,0x37,0x16,0x02,0x21,0x00,0x8E,0x21,0xF6,0x0E,0x44,0xC6,0x06,0x6C,
			 0x8B,0x8A,0x95,0xA3,0xC0,0x9D,0x3A,0xD4,0x37,0x95,0x85,0xA2,0xD7,0x28,0xEE,0xAD,
			 0x07,0xA1,0x7E,0xD7,0xAA,0x05,0x5E,0xCA
			};
	
	// Resembles the prefix 192.0.2.0/24
	uint8_t nlri[] = {
			 0x18,0xC0,0x00,0x02
			};

	for (int i = 0; i < as_hops; i++) {
		ss[i] = malloc(sizeof(struct signature_seg));
		if (ss[i] == NULL)
			assert(-1);

		sps[i] = malloc(sizeof(struct secure_path_seg));
		if (sps[i] == NULL)
			assert(-1);
	}

	spki_table_init(&table, NULL);
	// TODO: Check, if SKI was stored in the records correctly. Do this
	// by printing out the ski as a byte sequence in the validation function.
	struct spki_record *record1 = create_record(65536, ski1, 0, NULL);
	struct spki_record *record2 = create_record(64496, ski2, 1, NULL);
	struct spki_record *router_keys = malloc(sizeof(struct spki_record) * as_hops);
	unsigned int router_keys_len;

	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);

	spki_table_search_by_ski(&table, record1->ski,
				 &router_keys, &router_keys_len);

	// init the signature_seg and secure_path_seg structs.
	ss[0]->ski		= &ski1;
	ss[0]->sig_len		= 72;
	ss[0]->signature	= &sig1;

	sps[0]->pcount		= 1;
	sps[0]->conf_seg	= 0;
	sps[0]->asn		= 65536;

	ss[1]->ski		= &ski2;
	ss[1]->sig_len		= 72;
	ss[1]->signature	= &sig2;

	sps[1]->pcount		= 1;
	sps[1]->conf_seg	= 0;
	sps[1]->asn		= 64496;
	
	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65537;
	bg->nlri_len		= 4;
	bg->nlri		= &nlri;

	result = bgpsec_validate_as_path(bg, &ss, &sps, &table, as_hops);
	assert(result == BGPSEC_VALID);
	
	free(record1);
	free(record2);
	free(ss[0]);
	free(ss[1]);
	free(sps[0]);
	free(sps[1]);
	free(bg);
}

static void bgpsec_version_and_algorithms_test(void)
{
	// BGPsec version tests
	assert(bgpsec_get_version() == 0);

	assert(bgpsec_get_version() != 1);

	// BGPsec algorithm suite tests
	assert(bgpsec_check_algorithm_suite(1) == 0);

	assert(bgpsec_check_algorithm_suite(2) == 1);

	// BGPsec algorithm suites array test
	/*char *suites;*/
	/*int suites_len = bgpsec_get_algorithm_suites_arr(suites);*/
	/*for (int i = 0; i < suites_len; i++)*/
		/*assert(suites[i] == 1);*/
}



#endif

int main(void)
{
#ifdef BGPSEC
	bgpsec_version_and_algorithms_test();
	init_structs();
	printf("Test successful\n");
#endif
	return EXIT_SUCCESS;
}
