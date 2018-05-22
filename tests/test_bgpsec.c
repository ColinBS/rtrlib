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

#ifdef BGPSEC

/*struct size_uint8_test {*/
	/*uint8_t x;*/
/*};*/

/*struct size_2uint8_test {*/
	/*uint8_t x;*/
	/*uint8_t y;*/
/*};*/

/*struct size_uint16_test {*/
	/*uint16_t x;*/
/*};*/

/*struct size_uint8_16_test {*/
	/*uint8_t x;*/
	/*uint16_t y;*/
/*};*/

/*struct size_uint16_8_test {*/
	/*uint16_t y;*/
	/*uint8_t x;*/
/*};*/

/*static void struct_sizes(void)*/
/*{*/
	/*struct secure_path_seg sps;*/
	/*struct signature_seg ss;*/
	/*struct bgpsec_data bg;*/
	/*struct secure_path_seg_v2 sps_v2;*/
	/*struct signature_seg_v2 ss_v2;*/
	/*struct bgpsec_data_v2 bg_v2;*/
	/*struct size_uint8_test t;*/
	/*struct size_2uint8_test t2;*/
	/*struct size_uint16_test t3;*/
	/*struct size_uint8_16_test t4;*/
	/*struct size_uint16_8_test t5;*/

	/*uint8_t bytes[] = {*/
			   /*0x01,0x23,0x45,0x67,0x89,*/
			   /*0xAB,0xCD,0xEF,0x01,0x23,*/
			   /*0x45,0x67,0x89,0xAB,0xCD,*/
			   /*0xEF,0x01,0x23,0x45,0x67,*/
			  /*};*/

	/*printf("###################################\n");*/
	/*printf("%-30s%5s\n", "Structure", "Bytes");*/
	/*printf("-----------------------------------\n");*/
	/*printf("%-30s%5lu\n", "Size of uint8_t:", sizeof(uint8_t));*/
	/*printf("%-30s%5lu\n", "Size of uint16_t:", sizeof(uint16_t));*/
	/*printf("%-30s%5lu\n", "Size of uint32_t:", sizeof(uint32_t));*/
	/*printf("%-30s%5lu\n", "Size of uint64_t:", sizeof(uint64_t));*/
	/*printf("%-30s%5lu\n", "Size of secure_path_seg:", sizeof(sps));*/
	/*printf("%-30s%5lu\n", "Size of signature_seg:", sizeof(ss));*/
	/*printf("%-30s%5lu\n", "Size of bgpsec_data:", sizeof(bg));*/
	/*printf("%-30s%5lu\n", "Size of secure_path_seg_v2:", sizeof(sps_v2));*/
	/*printf("%-30s%5lu\n", "Size of signature_seg_v2:", sizeof(ss_v2));*/
	/*printf("%-30s%5lu\n", "Size of bgpsec_data_v2:", sizeof(bg_v2));*/
	/*printf("%-30s%5lu\n", "Size of target_as:", sizeof(bg.target_as));*/
	/*printf("%-30s%5lu\n", "Size of size_uint8_test:", sizeof(t));*/
	/*printf("%-30s%5lu\n", "Size of size_2uint8_test:", sizeof(t2));*/
	/*printf("%-30s%5lu\n", "Size of size_uint16_test:", sizeof(t3));*/
	/*printf("%-30s%5lu\n", "Size of size_uint8_16_test:", sizeof(t4));*/
	/*printf("%-30s%5lu\n", "Size of size_uint16_8_test:", sizeof(t5));*/
	/*printf("%-30s%5lu\n", "Size of bytes:", sizeof(bytes));*/
	/*printf("###################################\n");*/
/*}*/

static struct spki_record *create_record(int ASN, uint8_t *ski)
{
	struct spki_record *record = malloc(sizeof(struct spki_record));

	memset(record, 0, sizeof(*record));
	record->asn = ASN;
	memcpy(record->ski, ski, SKI_SIZE);

	record->socket = NULL;
	return record;
}

static void init_structs(void)
{
	enum bgpsec_rtvals retval;
	enum bgpsec_result result;
	int as_hops = 2;

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
			 0x01,0x02,0x03,0x04,0x05,
			 0x06,0x07,0x08,0x09,0x0A,
			 0x0B,0x0C,0x0D,0x0E,0x0F,
			 0x10,0x11,0x12,0x13,0x14,
			};

	uint8_t ski2[]  = {
			 0x11,0x12,0x13,0x14,0x15,
			 0x16,0x17,0x18,0x19,0x1A,
			 0x1B,0x1C,0x1D,0x1E,0x1F,
			 0x20,0x21,0x22,0x23,0x24,
			};

	uint8_t sig1[]  = {
			 0x01,0x02,0x03,0x04,0x05,
			};

	uint8_t sig2[]  = {
			 0x06,0x07,0x08,0x09,0x0A,
			};
	
	uint8_t nlri[] = {
			 0x08, 0x01,
			};

	for (int i = 0; i < as_hops; i++) {
		ss[i] = malloc(sizeof(struct signature_seg));
		if (ss[i] == NULL)
			assert(-1);

		sps[i] = malloc(sizeof(struct secure_path_seg));
		if (sps[i] == NULL)
			assert(-1);
	}

	// init the signature_segment structs.
	ss[0]->ski		= &ski1;
	ss[0]->sig_len		= 0x5;
	ss[0]->signature	= &sig1;

	ss[1]->ski		= &ski2;
	ss[1]->sig_len		= 0x5;
	ss[1]->signature	= &sig2;
	
	// init the secure_path_segment structs.
	sps[0]->pcount		= 0x1;
	sps[0]->conf_seg	= 0x0;
	sps[0]->asn		= 0x1;

	sps[1]->pcount		= 0x0;
	sps[1]->conf_seg	= 0x1;
	sps[1]->asn		= 0x2;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 0x1;
	bg->afi			= 0x1;
	bg->safi		= 0x1;
	bg->nlri_len		= 0x2;
	bg->nlri		= &nlri;

	retval = bgpsec_validate_as_path(bg, &ss, &sps, as_hops, &result);
	assert(retval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);
	
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
	assert(bgpsec_check_algorithm_suite(0x0) == 0);

	assert(bgpsec_check_algorithm_suite(0x1) == 1);
}

#endif

int main(void)
{
#ifdef BGPSEC
	/*struct_sizes();*/
	bgpsec_version_and_algorithms_test();
	init_structs();
	printf("Test successful\n");
#endif
	return EXIT_SUCCESS;
}
