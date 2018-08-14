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

#ifdef BGPSEC

#include "rtrlib/bgpsec/bgpsec.h"

const uint8_t ski1[]  = {
		 0x47,0xF2,0x3B,0xF1,0xAB,
		 0x2F,0x8A,0x9D,0x26,0x86,
		 0x4E,0xBB,0xD8,0xDF,0x27,
		 0x11,0xC7,0x44,0x06,0xEC
};

const uint8_t sig1[]  = {
		 0x30,0x46,0x02,0x21,0x00,0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,
		 0x9C,0xD4,0x5E,0x81,0xD6,0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,
		 0xA8,0x4E,0xAF,0x37,0x16,0x02,0x21,0x00,0x90,0xF2,0xC1,0x29,0xAB,0xB2,0xF3,0x9B,
		 0x6A,0x07,0x96,0x3B,0xD5,0x55,0xA8,0x7A,0xB2,0xB7,0x33,0x3B,0x7B,0x91,0xF1,0x66,
		 0x8F,0xD8,0x61,0x8C,0x83,0xFA,0xC3,0xF1
};

const uint8_t spki1[] = {
		    0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,
		    0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,
		    0x04,0x28,0xFC,0x5F,0xE9,0xAF,0xCF,0x5F,0x4C,0xAB,0x3F,0x5F,0x85,0xCB,0x21,
                    0x2F,0xC1,0xE9,0xD0,0xE0,0xDB,0xEA,0xEE,0x42,0x5B,0xD2,0xF0,0xD3,0x17,0x5A,
                    0xA0,0xE9,0x89,0xEA,0x9B,0x60,0x3E,0x38,0xF3,0x5F,0xB3,0x29,0xDF,0x49,0x56,
                    0x41,0xF2,0xBA,0x04,0x0F,0x1C,0x3A,0xC6,0x13,0x83,0x07,0xF2,0x57,0xCB,0xA6,
		    0xB8,0xB5,0x88,0xF4,0x1F
};

const uint8_t ski2[]  = {
		 0xAB,0x4D,0x91,0x0F,0x55,
		 0xCA,0xE7,0x1A,0x21,0x5E,
		 0xF3,0xCA,0xFE,0x3A,0xCC,
		 0x45,0xB5,0xEE,0xC1,0x54
};

const uint8_t sig2[]  = {
		 0x30,0x46,0x02,0x21,0x00,0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,
		 0x9C,0xD4,0x5E,0x81,0xD6,0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,
		 0xA8,0x4E,0xAF,0x37,0x16,0x02,0x21,0x00,0x8E,0x21,0xF6,0x0E,0x44,0xC6,0x06,0x6C,
		 0x8B,0x8A,0x95,0xA3,0xC0,0x9D,0x3A,0xD4,0x37,0x95,0x85,0xA2,0xD7,0x28,0xEE,0xAD,
		 0x07,0xA1,0x7E,0xD7,0xAA,0x05,0x5E,0xCA
};

const uint8_t spki2[] = {
		    0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,
		    0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,
		    0x04,0x73,0x91,0xBA,0xBB,0x92,0xA0,0xCB,0x3B,0xE1,0x0E,0x59,0xB1,0x9E,0xBF,
                    0xFB,0x21,0x4E,0x04,0xA9,0x1E,0x0C,0xBA,0x1B,0x13,0x9A,0x7D,0x38,0xD9,0x0F,
                    0x77,0xE5,0x5A,0xA0,0x5B,0x8E,0x69,0x56,0x78,0xE0,0xFA,0x16,0x90,0x4B,0x55,
                    0xD9,0xD4,0xF5,0xC0,0xDF,0xC5,0x88,0x95,0xEE,0x50,0xBC,0x4F,0x75,0xD2,0x05,
                    0xA2,0x5B,0xD3,0x6F,0xF5
};

const uint8_t private_key = {
		    0x30,0x77,0x02,0x01,0x01,0x04,0x20,
		    0xD8,0xAA,0x4D,0xFB,0xE2,0x47,0x8F,0x86,0xE8,0x8A,0x74,0x51,0xBF,0x07,0x55,
		    0x65,0x70,0x9C,0x57,0x5A,0xC1,0xC1,0x36,0xD0,0x81,0xC5,0x40,0x25,0x4C,0xA4,
		    0x40,0xB9,0xA0,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0xA1,
		    0x44,0x03,0x42,0x00,
		    0x04,0x73,0x91,0xBA,0xBB,0x92,0xA0,0xCB,0x3B,0xE1,0x0E,0x59,0xB1,0x9E,0xBF,
		    0xFB,0x21,0x4E,0x04,0xA9,0x1E,0x0C,0xBA,0x1B,0x13,0x9A,0x7D,0x38,0xD9,0x0F,
		    0x77,0xE5,0x5A,0xA0,0x5B,0x8E,0x69,0x56,0x78,0xE0,0xFA,0x16,0x90,0x4B,0x55,
		    0xD9,0xD4,0xF5,0xC0,0xDF,0xC5,0x88,0x95,0xEE,0x50,0xBC,0x4F,0x75,0xD2,0x05,
		    0xA2,0x5B,0xD3,0x6F,0xF5
};

const uint8_t wrong_sig[]  = {
		 0x30,0x46,0x02,0x21,0x00,0xEF,0xD4,0x8B,0x2A,0xAC,0xB6,0xA8,0xFD,0x11,0x40,0xDD,
		 0x9C,0xD4,0x5E,0x81,0xD6,0x9D,0x2C,0x87,0x7B,0x56,0xAA,0xF9,0x91,0xC3,0x4D,0x0E,
		 0xA8,0x4E,0xAF,0x37,0x16,0x02,0x21,0x00,0x8E,0x21,0xF6,0x0E,0x44,0xC6,0x06,0x6C,
		 0x8B,0x8A,0x95,0xA3,0xC0,0x9D,0x3A,0xD4,0x37,0x95,0x85,0xA2,0xD7,0x28,0xEE,0xAD,
		 0x07,0xA1,0x7E,0xD7,0xAA,0x05,0x5E,0xCB
};

const uint8_t wrong_spki[] = {
		    0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,0x2A,
		    0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,
		    0x04,0x73,0x91,0xBA,0xBB,0x92,0xA0,0xCB,0x3B,0xE1,0x0E,0x59,0xB1,0x9E,0xBF,
		    0xFB,0x21,0x4E,0x04,0xA9,0x1E,0x0C,0xBA,0x1B,0x13,0x9A,0x7D,0x38,0xD9,0x0F,
		    0x77,0xE5,0x5A,0xA0,0x5B,0x8E,0x69,0x56,0x78,0xE0,0xFA,0x16,0x90,0x4B,0x55,
		    0xD9,0xD4,0xF5,0xC0,0xDF,0xC5,0x88,0x95,0xEE,0x50,0xBC,0x4F,0x75,0xD2,0x05,
		    0xA2,0x5B,0xD3,0x6F,0xF6
};

// Resembles the prefix 192.0.2.0/24
const uint8_t nlri[] = {
		 0x18,0xC0,0x00,0x02
};

const char ski_str[]	= "AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC154";
const char wrong_ski[]	= "AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC155";

static struct spki_record *create_record(int ASN,
					 uint8_t *ski,
					 uint8_t *spki)
{
	u_int32_t i;
	struct spki_record *record = malloc(sizeof(struct spki_record));

	memset(record, 0, sizeof(*record));
	record->asn = ASN;
	memcpy(record->ski, ski, SKI_SIZE);
	memcpy(record->spki, spki, SPKI_SIZE);

	record->socket = NULL;
	return record;
}

static void validate_bgpsec_path_test(void)
{
	struct spki_table table;
	struct spki_record *record1;
	struct spki_record *record2;
	struct spki_record *duplicate_record;
	struct spki_record *wrong_record;

	enum bgpsec_result result;
	int as_hops;

	// AS(64496)--->AS(65536)--->AS(65537)

	/* The size in bytes of one signature_seg in this test case is:
	 * 20 * 1 (ski) +
	 * 2 (sig_len) +
	 * 71 * 1 (signature)
	 * -----------
	 * 93
	 */
	struct signature_seg *ss;

	/* The size in bytes of one secure_path_seg in this test case is:
	 * 1 (pcount) +
	 * 1 (conf_seg) +
	 * 4 (asn)
	 * -----------
	 * 6
	 */
	struct secure_path_seg *sps;

	/* The size in bytes (used for digestion) of bgpsec_data in this test case is:
	 * 4 (asn)
	 * 1 (alg_suite_id) +
	 * 2 (afi) +
	 * 1 (safi) +
	 * 4 * 1 (nlri)
	 * -----------
	 * 12
	 */
	struct bgpsec_data *bg;

	/* In total, the raw data that is processed by the validation
	 * function in this test case is:
	 * 2 * 93 (sig_segs)
	 * 2 * 6 (seg_path_segs)
	 * 12 (bgpsec_data)
	 * -----------
	 * 210
	 */

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 2;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[0].ski		= &ski1;
	ss[0].sig_len		= 72;
	ss[0].signature		= &sig1;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65536;

	ss[1].ski		= &ski2;
	ss[1].sig_len		= 72;
	ss[1].signature		= &sig2;

	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 64496;
	
	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65537;
	/*bg->asn			= 65536;*/
	bg->nlri_len		= 4;
	bg->nlri		= &nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(65536, ski1, spki1);
	record2 = create_record(64496, ski2, spki2);
	duplicate_record = create_record(64497, ski2, spki1);
	wrong_record = create_record(65536, ski1, wrong_spki);

	spki_table_add_entry(&table, duplicate_record);
	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);

	assert(result == BGPSEC_VALID);

	// Pass a wrong signature.
	// (table = duplicate_record, record1, record2)
	ss[1].signature = &wrong_sig;
	result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);

	assert(result == BGPSEC_NOT_VALID);

	ss[1].signature = &sig2;

	// Pass a wrong public key
	// (table = duplicate_record, record2, wrong_record)
	spki_table_remove_entry(&table, record1);
	spki_table_add_entry(&table, wrong_record);

	result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);

	assert(result == BGPSEC_ERROR);

	// Public key not in SPKI table
	// (table = duplicate_record, record2)
	spki_table_remove_entry(&table, wrong_record);

	result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);

	assert(result == BGPSEC_ERROR);

	// What if there are mulitple SPKI entries for a SKI in the SPKI table.
	// (table = duplicate_record, record2, record1)
	spki_table_add_entry(&table, record1);

	result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);

	assert(result == BGPSEC_VALID);

	// Pass an unsupported algorithm suite.
	bg->alg_suite_id = 2;

	result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);

	assert(result == BGPSEC_UNSUPPORTED_ALGORITHM_SUITE);

	// Free all allocated memory.
	spki_table_free(&table);
	free(record1);
	free(record2);
	free(wrong_record);
	free(duplicate_record);
	free(ss);
	free(sps);
	free(bg);
}

static void generate_signature_test(void)
{
	struct spki_table table;
	struct spki_record *record1;
	struct spki_record *record2;

	int as_hops;
	int sig_len;
	int target_as;

	// AS(64496)--->AS(65536)--->AS(65537)

	/* The size in bytes of one signature_seg in this test case is:
	 * 20 * 1 (ski) +
	 * 2 (sig_len) +
	 * 72 * 1 (signature)
	 * -----------
	 * 94
	 */
	struct signature_seg *ss;

	/* The size in bytes of one secure_path_seg in this test case is:
	 * 1 (pcount) +
	 * 1 (conf_seg) +
	 * 4 (asn)
	 * -----------
	 * 6
	 */
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;

	/* The size in bytes (used for digestion) of bgpsec_data in this test case is:
	 * 4 (asn)
	 * 1 (alg_suite_id) +
	 * 2 (afi) +
	 * 1 (safi) +
	 * 4 * 1 (nlri)
	 * -----------
	 * 12
	 */
	struct bgpsec_data *bg;

	/* In total, the raw data that is processed by the validation
	 * function in this test case is:
	 * 2 * 93 (sig_segs)
	 * 2 * 6 (seg_path_segs)
	 * 12 (bgpsec_data)
	 * -----------
	 * 210
	 */

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 1;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The own AS information.
	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65536;

	// The previous AS information.
	ss[0].ski		= &ski1;
	ss[0].sig_len		= 72;
	ss[0].signature		= &sig1;

	own_sp[1].pcount	= 1;
	own_sp[1].conf_seg	= 0;
	own_sp[1].asn		= 64496;
	
	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= &nlri;

	target_as = 65537;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);
	record2 = create_record(65536, ski2, spki2);

	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	// TODO: allocation with magic numbers is bad...
	char *new_sig = malloc(72);
	sig_len = rtr_bgpsec_create_signature(bg, ss, sps, &table, as_hops,
					      own_sp, target_as, &ski_str,
					      &private_key, new_sig);

	assert(sig_len > 0);

	// Free all allocated memory.
	free(record1);
	free(record2);
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);
	spki_table_free(&table);
}

static void originate_update_test(void)
{
	struct spki_table table;
	struct spki_record *record1;

	int as_hops;
	int sig_len;
	int status;
	int target_as;

	// AS(64496)--->AS(65536)--->AS(65537)

	/* The size in bytes of one secure_path_seg in this test case is:
	 * 1 (pcount) +
	 * 1 (conf_seg) +
	 * 4 (asn)
	 * -----------
	 * 6
	 */
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;

	/* The size in bytes (used for digestion) of bgpsec_data in this test case is:
	 * 4 (asn)
	 * 1 (alg_suite_id) +
	 * 2 (afi) +
	 * 1 (safi) +
	 * 4 * 1 (nlri)
	 * -----------
	 * 12
	 */
	struct bgpsec_data *bg;

	/* In total, the raw data that is processed by the validation
	 * function in this test case is:
	 * 2 * 93 (sig_segs)
	 * 2 * 6 (seg_path_segs)
	 * 12 (bgpsec_data)
	 * -----------
	 * 210
	 */

	as_hops = 0;
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The own AS information.
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 64496;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= &nlri;

	target_as = 65536;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski2, spki2);

	spki_table_add_entry(&table, record1);

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	// TODO: allocation with magic numbers is bad...
	char *new_sig1 = malloc(72);
	if (new_sig1 == NULL)
		assert(0);
	sig_len = rtr_bgpsec_create_signature(bg, NULL, NULL, &table, as_hops,
					      own_sp, target_as, &ski_str,
					      &private_key, new_sig1);

	assert(sig_len > 0);

	// Wrong SKI of private key.
	char *new_sig2 = malloc(72);
	if (new_sig2 == NULL)
		assert(0);
	status = rtr_bgpsec_create_signature(bg, NULL, NULL, &table, as_hops,
					     own_sp, target_as, &wrong_ski,
					     &private_key, new_sig2);

	assert(status == BGPSEC_LOAD_PRIV_KEY_ERROR);

	// Free all allocated memory.
	free(record1);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig1);
	free(new_sig2);
	spki_table_free(&table);
}

static void bgpsec_version_and_algorithms_test(void)
{
	// BGPsec version tests
	assert(rtr_bgpsec_get_version() == 0);

	assert(rtr_bgpsec_get_version() != 1);

	// BGPsec algorithm suite tests
	assert(rtr_bgpsec_check_algorithm_suite(1) == BGPSEC_SUCCESS);

	assert(rtr_bgpsec_check_algorithm_suite(2) == BGPSEC_ERROR);

	// BGPsec algorithm suites array test
	int *suites = NULL;
	int suites_len = rtr_bgpsec_get_algorithm_suites_arr(&suites);
	assert(suites_len == 1);
	for (int i = 0; i < suites_len; i++)
		assert(suites[i] == 1);
} 

#endif

int main(void)
{
#ifdef BGPSEC
	bgpsec_version_and_algorithms_test();
	validate_bgpsec_path_test();
	generate_signature_test();
	originate_update_test();
	printf("Test successful\n");
#endif
	return EXIT_SUCCESS;
}
