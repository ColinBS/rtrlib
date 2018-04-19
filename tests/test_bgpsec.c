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
#include "rtrlib/rtrlib.h"

#ifdef BGPSEC

struct size_uint8_test {
	uint8_t x;
};

struct size_2uint8_test {
	uint8_t x;
	uint8_t y;
};

struct size_uint16_test {
	uint16_t x;
};

struct size_uint8_16_test {
	uint8_t x;
	uint16_t y;
};

struct size_uint16_8_test {
	uint16_t y;
	uint8_t x;
};

// Taken from http://www.askyb.com/cpp/openssl-sha256-hashing-example-in-cpp/
static void ssl_test(void)
{
	// This is the input test string.
	char string[] = "Test String";
	// This is the expected result.
	char exp[] = "30c6ff7a44f7035af933babaea771bf177fc38f06482ad06434cbcc04de7ac14";
	// This is the array where the result of the SHA256 operation is stored in.
	// It is initialized to hold exactly the amount of characters that SHA256 produces.
	unsigned char digest[SHA256_DIGEST_LENGTH];

	// SHA256 takes the input string, the amount of characters to read (in this case
	// all) and the output array where to store the result in.
	SHA256((unsigned char*)&string, strlen(string), (unsigned char*)&digest);

	// Here is some debug output. First, print the integer representation of the
	// SHA256 result. Second, print the hex representation of the integer.
	// Do this with the first 5 positions.
	//    printf("Pos 0: %d, %02x\n", (unsigned int)digest[0], (unsigned int)digest[0]);
	//    printf("Pos 1: %d, %02x\n", (unsigned int)digest[1], (unsigned int)digest[1]);
	//    printf("Pos 2: %d, %02x\n", (unsigned int)digest[2], (unsigned int)digest[2]);
	//    printf("Pos 3: %d, %02x\n", (unsigned int)digest[3], (unsigned int)digest[3]);
	//    printf("Pos 4: %d, %02x\n", (unsigned int)digest[4], (unsigned int)digest[4]);

	// The result of the string representation has to be twice as large as the
	// SHA256 result array. This is because the hex representation of a single char
	// has a length of two, e.g. to represent the hex number 30 we need two characters,
	// "3" and "0".
	// The additional +1 is because of the terminating '\0' character.
	char result[SHA256_DIGEST_LENGTH*2+1];

	// Feed the converted chars into the result array. "%02x" means, print at least
	// two characters and add leading zeros, if necessary. The "x" stands for integer.
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);

	//printf("SHA256 digest: %s\n", result);
	// Assert the result string and the expected string.
	assert(strcmp(result, exp) == 0);
}

static void struct_sizes(void)
{
	struct secure_path_seg sps;
	struct signature_seg ss;
	struct bgpsec_data bg;
	struct size_uint8_test t;
	struct size_2uint8_test t2;
	struct size_uint16_test t3;
	struct size_uint8_16_test t4;
	struct size_uint16_8_test t5;

	uint8_t bytes[] = {
			   0x01,0x23,0x45,0x67,0x89,
			   0xAB,0xCD,0xEF,0x01,0x23,
			   0x45,0x67,0x89,0xAB,0xCD,
			   0xEF,0x01,0x23,0x45,0x67,
			  };

	printf("###################################\n");
	printf("%-30s%5s\n", "Structure", "Bytes");
	printf("-----------------------------------\n");
	printf("%-30s%5lu\n", "Size of uint8_t:", sizeof(uint8_t));
	printf("%-30s%5lu\n", "Size of uint16_t:", sizeof(uint16_t));
	printf("%-30s%5lu\n", "Size of uint32_t:", sizeof(uint32_t));
	printf("%-30s%5lu\n", "Size of uint64_t:", sizeof(uint64_t));
	printf("%-30s%5lu\n", "Size of secure_path_seg:", sizeof(sps));
	printf("%-30s%5lu\n", "Size of signature_seg:", sizeof(ss));
	printf("%-30s%5lu\n", "Size of bgpsec_data:", sizeof(bg));
	printf("%-30s%5lu\n", "Size of size_uint8_test:", sizeof(t));
	printf("%-30s%5lu\n", "Size of size_2uint8_test:", sizeof(t2));
	printf("%-30s%5lu\n", "Size of size_uint16_test:", sizeof(t3));
	printf("%-30s%5lu\n", "Size of size_uint8_16_test:", sizeof(t4));
	printf("%-30s%5lu\n", "Size of size_uint16_8_test:", sizeof(t5));
	printf("%-30s%5lu\n", "Size of bytes:", sizeof(bytes));
	printf("###################################\n");
}

/**
 * @brief Create a SPKI record
 *
 * @return new SPKI record
 */
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
	struct signature_seg ss[1];
	struct secure_path_seg sps[1];
	struct bgpsec_data bg;

	enum bgpsec_rtvals retval;
	enum bgpsec_result result;

	uint8_t ski[] = {
			 0x01,0x23,0x45,0x67,0x89,
			 0xAB,0xCD,0xEF,0x01,0x23,
			 0x45,0x67,0x89,0xAB,0xCD,
			 0xEF,0x01,0x23,0x45,0x67,
			};

	uint8_t sig[] = {
			 0x01,0x23,0x45,0x67,0x89,
			 0xAB,0xCD,0xEF,0x01,0x23,
			};
	
	uint8_t nlri = {
			0x08, 0x01,
		       };

	/*struct spki_record *record = create_record(1, ski);*/

	// init the first signature_segment struct.
	memcpy(ss[0].ski, ski, SKI_SIZE); // 20 bytes.
	ss[0].sig_len	= 0xA; // 10
	ss[0].signature	= sig; // 10 bytes;
	
	// init the first secure_path_segment struct.
	sps[0].pcount	= 0x1;
	sps[0].conf_seg	= 0x0;
	sps[0].asn	= 0x1;

	// init the first bgpsec_data struct.
	bg.target_as	= 0x2;
	bg.alg_suite_id = 0x1;
	bg.afi		= 0x1;
	bg.safi		= 0x1;
	bg.nlri		= nlri;
	bg.nlri_len	= 0x2;

	retval = bgpsec_validate_as_path(&bg, ss, 1, sps, 1, 2, &result);
	assert(retval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);
}
#endif

int main(void)
{
#ifdef BGPSEC
	ssl_test();
	struct_sizes();
	init_structs();
	printf("Test successful\n");
#endif
	return EXIT_SUCCESS;
}
