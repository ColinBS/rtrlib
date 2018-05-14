/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "rtrlib/bgpsec/bgpsec.h"

#define BYTES_MAX_LEN	1024

int bgpsec_validate_as_path(const struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    const unsigned int as_hops,
			    enum bgpsec_result *result)
{
	int bytes_size;
	int offset = 0;
	// The size of all passed Signature Segments.
	int sig_seg_size = (sizeof(uint8_t) * sig_segs->sig_len) +
			   sizeof(sig_segs->sig_len) +
			   (sizeof(uint8_t) * SKI_SIZE);
	// The size of the passed NLRI.
	int nlri_size = sizeof(uint8_t) * data->nlri_len;

	// Calculate the necessary size of bytes
	// bgpsec_data struct is 8 + 16 + 16 + 16 + (nlri_len * 8)
	bytes_size = 56 + nlri_size;
	bytes_size += sig_seg_size * as_hops;
	bytes_size += SECURE_PATH_SEGMENT_SIZE * as_hops;

	uint8_t *bytes = malloc(bytes_size);

	if (bytes == NULL)
		return RTR_BGPSEC_ERROR;

	memset(bytes, 0, bytes_size);

	memcpy(&bytes[offset], &(sec_paths->asn), sizeof(sec_paths->asn));
	offset += sizeof(sec_paths->asn);

	for (int i = (as_hops - 1); i >= 0; i--) {
		memcpy(&bytes[offset], &(sec_paths->pcount), sizeof(sec_paths->pcount));
		offset += sizeof(sec_paths->pcount);
		memcpy(&bytes[offset], &(sec_paths->conf_seg), sizeof(sec_paths->conf_seg));
		offset += sizeof(sec_paths->conf_seg);
		memcpy(&bytes[offset], &(sec_paths->asn), sizeof(sec_paths->asn));
		offset += sizeof(sec_paths->asn);
	}
	for (int i = (as_hops - 1); i >= 0; i--) {
		memcpy(&bytes[offset], sig_segs->ski, SKI_SIZE);
		offset += SKI_SIZE;
		memcpy(&bytes[offset], &(sig_segs->sig_len), sizeof(sig_segs->sig_len));
		offset += sizeof(sig_segs->sig_len);
		memcpy(&bytes[offset], sig_segs->signature, sig_segs->sig_len);
		offset += sig_segs->sig_len;
	}
	for (int i = 0; i < bytes_size; i++)
		printf("%2x", (char)bytes[i]);
	printf("\n");
	*result = BGPSEC_VALID;
	free(bytes);
	return RTR_BGPSEC_SUCCESS;

	/*for (int i = 0; i < SKI_SIZE; i++)*/
		/*printf("%c\n", (char)sig_segs->ski[i] + 48);*/

	/*for (int i = 0; i < sig_segs->sig_len; i++)*/
		/*printf("%c\n", (char)sig_segs->signature[i] + 48);*/

	/*uint8_t *foo = malloc(sizeof(uint8_t) * sig_segs->sig_len);*/
	/*memcpy(foo, sig_segs->signature, sig_segs->sig_len);*/
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

int bgpsec_get_algorithm_suite(int alg_suite)
{
	if (alg_suite == BGPSEC_ALGORITHM_SUITE_1)
		return 1;
	else
		return 0;
}
