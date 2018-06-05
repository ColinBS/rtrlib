/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "rtrlib/bgpsec/bgpsec.h"
#include "rtrlib/spki/hashtable/ht-spkitable.h"

void _print_byte_sequence(const unsigned char *bytes,
			  unsigned int bytes_size,
			  char alignment);

void _bgpsec_print_segment(struct signature_seg *sig_seg,
			   struct secure_path_seg *sec_path);

/*
 * The data for digestion must be ordered exactly like this:
 *
 * +------------------------------------+
 * | Target AS Number                   |
 * +------------------------------------+----\
 * | Signature Segment   : N-1          |     \
 * +------------------------------------+     |
 * | Secure_Path Segment : N            |     |
 * +------------------------------------+     \
 *       ...                                  >  Data from
 * +------------------------------------+     /   N Segments
 * | Signature Segment   : 1            |     |
 * +------------------------------------+     |
 * | Secure_Path Segment : 2            |     |
 * +------------------------------------+     /
 * | Secure_Path Segment : 1            |    /
 * +------------------------------------+---/
 * | Algorithm Suite Identifier         |
 * +------------------------------------+
 * | AFI                                |
 * +------------------------------------+
 * | SAFI                               |
 * +------------------------------------+
 * | NLRI                               |
 * +------------------------------------+
 *
 * https://tools.ietf.org/html/rfc8205#section-4.2
 */

/* The arrays are passed in "AS path order", meaning the last appeded
 * Signature Segment / Secure_Path Segment is at the first
 * position of the array.
 */

int bgpsec_calculate_digest(struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    const unsigned int as_hops,
			    uint8_t **bytes)
{
	int bytes_size;
	int sig_segs_size = 0;

	uint8_t *bytes_start = NULL;

	// The size of all but the last appended Signature Segments
	// (which is the first element of the array).
	for (int i = 1; i < as_hops; i++) {
		sig_segs_size += sig_segs[i].sig_len +
				 sizeof(sig_segs[i].sig_len) +
				 SKI_SIZE;
	}

	// Calculate the total necessary size of bytes.
	// bgpsec_data struct in bytes is 4 + 1 + 2 + 1 + nlri_len
	bytes_size = 8 + data->nlri_len +
			 sig_segs_size +
			 (SECURE_PATH_SEGMENT_SIZE * as_hops);

	*bytes = malloc(bytes_size);

	if (*bytes == NULL)
		return RTR_BGPSEC_ERROR;

	memset(*bytes, 0, bytes_size);

	bytes_start = *bytes;

	// Begin here to assemble the data for the digestion.

	data->asn = ntohl(data->asn);
	memcpy(*bytes, &(data->asn), ASN_SIZE);
	*bytes += ASN_SIZE;

	for (unsigned int i = 0, j = 1; i < as_hops; i++, j++) {
		// Skip the first Signature Segment and go right to segment i+1
		if (j < as_hops) {
			memcpy(*bytes, sig_segs[j].ski, SKI_SIZE);
			*bytes += SKI_SIZE;

			sig_segs[j].sig_len = ntohs(sig_segs[j].sig_len);
			memcpy(*bytes, &(sig_segs[j].sig_len), SIG_LEN_SIZE);
			*bytes += SIG_LEN_SIZE;
			sig_segs[j].sig_len = htons(sig_segs[j].sig_len);

			memcpy(*bytes, sig_segs[j].signature,
			       sig_segs[j].sig_len);
			*bytes += sig_segs[j].sig_len;
		}

		// Secure Path Segment i
		sec_paths[i].asn = ntohl(sec_paths[i].asn);
		memcpy(*bytes, &sec_paths[i], sizeof(struct secure_path_seg));
		*bytes += sizeof(struct secure_path_seg);
	}

	// The rest of the BGPsec data.
	// The size of alg_suite_id + afi + safi.
	data->afi = ntohs(data->afi);
	memcpy(*bytes, data, 4);
	*bytes += 4;
	// TODO: make trailing bits 0.
	memcpy(*bytes, data->nlri, data->nlri_len);

	// Set the pointer of bytes to the beginning.
	*bytes = bytes_start;

	/*_print_byte_sequence(*bytes, bytes_size, 'v');*/

	return bytes_size;
}

int bgpsec_validate_as_path(struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    struct spki_table *table,
			    const unsigned int as_hops)
{
	int spki_count = 0;

	// bytes holds the byte sequence that is hashed.
	uint8_t *bytes;
	// bytes_start holds the start address of bytes.
	// This is necessary because bytes address is
	// incremented after every memcpy.
	uint8_t *bytes_start;

	// Before the validation process in triggered, make sure that
	// all router keys are present.
	
	unsigned int router_keys_len;
	struct spki_record *router_keys = malloc(sizeof(struct spki_record)
						 * as_hops);

	if (router_keys == NULL)
		return RTR_BGPSEC_ERROR;

	// Store all router keys.
	for (unsigned int i = 0; i < as_hops; i++) {
		struct spki_record *tmp_key;
		spki_table_search_by_ski(table, sig_segs[i].ski,
					 &tmp_key, &router_keys_len);
		memcpy(&router_keys[i], tmp_key, sizeof(struct spki_record));
		spki_count += router_keys_len;
		free(tmp_key);
	}

	// TODO: Make appropriate error values.
	if (spki_count < as_hops)
		return RTR_BGPSEC_ERROR;

	int bytes_len = bgpsec_calculate_digest(data, sig_segs, sec_paths,
						as_hops, &bytes);

	// Finished aligning the data.
	// Hashing begins here.

	uint8_t *result = malloc(SHA256_DIGEST_LENGTH);
	if (result == NULL)
		return RTR_BGPSEC_ERROR;

	hash_byte_sequence((const unsigned char *)bytes, bytes_len, result);

	// Finished hashing.
	// Store the router keys in OpenSSL structs.
	// TRYING TO FIGURE OUT HOW TO USE OPENSSL
	/*EC_KEY *x;*/
	/*unsigned char *p;*/
	/*int len = 71;*/

	/*p = router_keys[0].spki;*/
	/*x = d2i_EC_PUBKEY(NULL, &p, len);*/
	/*if (x == NULL)*/
	      /*return RTR_BGPSEC_ERROR;*/
	/*unsigned char *p = (unsigned char *)router_keys[0].spki;*/
	/*EC_KEY *ecdsa_key;*/
	/*ecdsa_key = d2i_EC_PUBKEY(&ecdsa_key, &p, 71);*/
	/*if (ecdsa_key == NULL)*/
		/*return RTR_BGPSEC_ERROR;*/

	free(bytes);
	free(result);
	free(router_keys);

	return BGPSEC_VALID;
}

void hash_byte_sequence(const unsigned char *bytes,
			unsigned int bytes_len,
			uint8_t *result_buffer)
{
	unsigned char result_hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, bytes, bytes_len);
	SHA256_Final(result_hash, &ctx);

	if (result_hash != NULL)
		memcpy(result_buffer, result_hash, SHA256_DIGEST_LENGTH);
}

void _print_byte_sequence(const unsigned char *bytes,
			  unsigned int bytes_size,
			  char alignment)
{
	int bytes_printed = 1;
	switch (alignment) {
	case 'h':
		for (unsigned int i = 0; i < bytes_size; i++)
			printf("Byte %d/%d: %02x\n", i+1, bytes_size, bytes[i]);
		break;
	case 'v':
	default:
		for (unsigned int i = 0; i < bytes_size; i++, bytes_printed++) {
			printf("%02x ", bytes[i]);

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

void _bgpsec_print_segment(struct signature_seg *sig_seg,
			   struct secure_path_seg *sec_path)
{
	char ski[SKI_SIZE*3+1];
	char signature[sig_seg->sig_len*3+1];

	for (int i = 0; i < SKI_SIZE; i++)
		sprintf(&ski[i*3], "%02x ", (uint8_t)sig_seg->ski[i]);

	for (int i = 0; i < sig_seg->sig_len; i++) {
		sprintf(&signature[i*3], "%02x ", (uint8_t)sig_seg->signature[i]);
	}

	printf("Signature Segment:\n\tSKI: %s\n\tLength: %d\n\tSignature: %s\n",
			ski,
			sig_seg->sig_len,
			signature);
	printf("Secure_Path Segment:\n\tpCount: %d\n\tFlags: %d\n\tAS number: %d\n",
			sec_path->pcount,
			sec_path->conf_seg,
			sec_path->asn);
	printf("\n");
}

int bgpsec_create_ec_key(EC_KEY **eckey)
{	
	int status;

	*eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey == NULL) {
		RTR_DBG1("ERROR: EC key could not be created");
		return RTR_BGPSEC_ERROR;
	}

	status = EC_KEY_generate_key(*eckey);
	if (status != 1) {
		RTR_DBG1("ERROR: EC key could not be generated");
		EC_KEY_free(*eckey);
		return RTR_BGPSEC_ERROR;
	}

	return RTR_BGPSEC_SUCCESS;
}

int bgpsec_create_ecdsa_signature(const char *str,
				  EC_KEY **eckey,
				  ECDSA_SIG **sig)
{
	if (strlen(str) < 1) {
		RTR_DBG1("ERROR: Empty input string");
		return RTR_BGPSEC_ERROR;
	}

	if (eckey == NULL) {
		RTR_DBG1("ERROR: Malformed EC key");
		return RTR_BGPSEC_ERROR;
	}

	*sig = ECDSA_do_sign((const unsigned char *)str, strlen(str), *eckey);
	if (sig == NULL) {
		RTR_DBG1("ERROR: EC Signature could not be generated");
		return RTR_BGPSEC_ERROR;
	}

	/*RTR_DBG1("Successfully generated EC Signature");*/
	return RTR_BGPSEC_SUCCESS;
}

int bgpsec_validate_ecdsa_signature(const char *str,
				    EC_KEY **eckey,
				    ECDSA_SIG **sig,
				    enum bgpsec_result *result)
{
	int rtval = RTR_BGPSEC_ERROR;
	int status;

	if (strlen(str) < 1) {
		RTR_DBG1("ERROR: Empty input string");
		return rtval;
	}

	if (eckey == NULL) {
		RTR_DBG1("ERROR: Malformed EC key");
		return rtval;
	}

	if (sig == NULL) {
		RTR_DBG1("ERROR: Malformed Signature");
		return rtval;
	}

	status = ECDSA_do_verify((const unsigned char *)str, strlen(str), *sig, *eckey);
	switch(status) {
	case -1:
		RTR_DBG1("ERROR: Failed to verify EC Signature");
		rtval = RTR_BGPSEC_ERROR;
		break;
	case 0:
		*result = BGPSEC_NOT_VALID;
		rtval = RTR_BGPSEC_SUCCESS;
		RTR_DBG1("Sucessfully verified EC Signature");
		break;
	case 1:
		*result = BGPSEC_VALID;
		rtval = RTR_BGPSEC_SUCCESS;
		RTR_DBG1("Sucessfully verified EC Signature");
		break;
	}

	return rtval;
}

int bgpsec_string_to_hash(const unsigned char *str,
			  unsigned char **result_hash)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	*result_hash = malloc(sizeof(digest));

	if (*result_hash == NULL)
		return RTR_BGPSEC_ERROR;

	SHA256(str, strlen(str), &digest);
	memcpy(*result_hash, digest, sizeof(digest));

	return RTR_BGPSEC_SUCCESS;
}

int bgpsec_hash_to_string(const unsigned char *hash,
			  unsigned char **result_str)
{
	// The result of the string representation has to be twice as large as the
	// SHA256 result array. This is because the hex representation of a single char
	// has a length of two, e.g. to represent the hex number 30 we need two characters,
	// "3" and "0".
	// The additional +1 is because of the terminating '\0' character.
	char hex[SHA256_DIGEST_LENGTH*2+1];
	*result_str = malloc(sizeof(hex));

	if (*result_str == NULL)
		return RTR_BGPSEC_ERROR;

	// Feed the converted chars into the result array. "%02x" means, print at least
	// two characters and add leading zeros, if necessary. The "x" stands for integer.
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&hex[i*2], "%02x", (unsigned int)hash[i]);

	memcpy(*result_str, hex, sizeof(hex));

	return RTR_BGPSEC_SUCCESS;
}

int bgpsec_get_version()
{
	return BGPSEC_VERSION;
}

int bgpsec_check_algorithm_suite(int alg_suite)
{
	if (alg_suite == BGPSEC_ALGORITHM_SUITE_1)
		return 0;
	else
		return 1;
}

/*int bgpsec_get_algorithm_suites_arr(char *algs_arr)*/
/*{*/
	/*static char arr[ALGORITHM_SUITES_COUNT] = {BGPSEC_ALGORITHM_SUITE_1};*/
	/*algs_arr = &arr;*/
	/*return ALGORITHM_SUITES_COUNT;*/
/*}*/
