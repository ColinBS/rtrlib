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
	/*struct signature_seg *ss = malloc(sizeof(struct signature_seg));*/
	/*struct secure_path_seg *sps = malloc(sizeof(struct secure_path_seg));*/
	struct bgpsec_data *bg = malloc(sizeof(struct bgpsec_data));
	/*memset(ss, 0, sizeof(struct signature_seg));*/
	/*memset(sps, 0, sizeof(struct secure_path_seg));*/
	memset(bg, 0, sizeof(struct bgpsec_data));

	struct signature_seg *ss[2] = malloc(sizeof(struct signature_seg) * 2);
	struct secure_path_seg *sps[2] = malloc(sizeof(struct secure_path_seg));
	struct bgpsec_data *bg = malloc(sizeof(struct bgpsec_data));
	enum bgpsec_rtvals retval;
	enum bgpsec_result result;

	uint8_t ski[]  = {
			 0x01,0x02,0x03,0x04,0x05,
			 0x06,0x07,0x08,0x09,0x0A,
			 0x0B,0x0C,0x0D,0x0E,0x0F,
			 0x10,0x11,0x12,0x13,0x14,
			};

	uint8_t sig[]  = {
			 0x01,0x02,0x03,0x04,0x05,
			 0x06,0x07,0x08,0x09,0x0A,
			};
	
	uint8_t nlri[] = {
			 0x08, 0x01,
			};

	/*struct spki_record *record = create_record(1, ski);*/

	// init the first signature_segment struct.
	ss->ski		= &ski;
	ss->sig_len	= 0xA; // 10
	ss->signature	= &sig;
	
	// init the first secure_path_segment struct.
	sps->pcount	= 0x1;
	sps->conf_seg	= 0x0;
	sps->asn	= 0x1;

	// init the first bgpsec_data struct.
	bg->alg_suite_id	= 0x1;
	bg->afi			= 0x1;
	bg->safi		= 0x1;
	bg->nlri_len		= 0x2;
	bg->nlri		= &nlri;
	/*memcpy(bg->nlri, nlri, bg->nlri_len);*/

	retval = bgpsec_validate_as_path(bg, ss, sps, 1, &result);
	assert(retval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);
}

static void bgpsec_version_and_algorithms_test(void)
{
	// BGPsec version tests
	assert(bgpsec_get_version() == 0);

	assert(bgpsec_get_version() != 1);

	// BGPsec algorithm suite tests
	assert(bgpsec_get_algorithm_suite(0x0) == 0);

	assert(bgpsec_get_algorithm_suite(0x1) == 1);
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
