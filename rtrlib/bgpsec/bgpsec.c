/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "rtrlib/bgpsec/bgpsec.h"

#define BGPSEC_DBG(fmt, ...) lrtr_dbg("BGPSEC: " fmt, ## __VA_ARGS__)
#define BGPSEC_DBG1(a) lrtr_dbg("BGPSEC: " a)

#define BUFFER_SIZE 500

void _print_byte_sequence(const unsigned char *bytes,
			  unsigned int bytes_size,
			  char alignment,
			  int tabstops);

void _print_bgpsec_segment(struct signature_seg *sig_seg,
			   struct secure_path_seg *sec_path);

void _ski_to_char(unsigned char *ski_str, uint8_t *ski);

int _align_val_byte_sequence(const struct bgpsec_data *data,
			     const struct signature_seg *sig_segs,
			     const struct secure_path_seg *sec_paths,
			     const unsigned int as_hops,
			     uint8_t **bytes,
			     int *bytes_len);

int _align_gen_byte_sequence(const struct bgpsec_data *data,
     			     const struct signature_seg *sig_segs,
     			     const struct secure_path_seg *sec_paths,
     			     const unsigned int as_hops,
     			     const struct secure_path_seg *own_sec_path,
     			     const unsigned int target_as,
     			     uint8_t **bytes,
     			     int *bytes_len);

int _hash_byte_sequence(const unsigned char *bytes,
			unsigned int bytes_len,
			const unsigned char *result_buffer);

int _validate_signature(const unsigned char *hash,
			uint8_t *signature,
			uint16_t sig_len,
			uint8_t *spki,
			uint8_t *ski);

int _get_sig_segs_size(const struct signature_seg *sig_segs,
		       const unsigned int sig_segs_len,
		       const unsigned int offset);

int _load_private_key(EC_KEY **priv_key, uint8_t *bytes_key);

int _load_public_key(EC_KEY **pub_key, uint8_t *spki);

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

int rtr_bgpsec_validate_as_path(const struct bgpsec_data *data,
				const struct signature_seg *sig_segs,
				const struct secure_path_seg *sec_paths,
				const struct spki_table *table,
				const unsigned int as_hops)
{
	// The AS path validation result.
	int retval;

	// bytes holds the byte sequence that is hashed.
	uint8_t *bytes = NULL;
	int bytes_len;

	// bytes_start holds the start address of bytes.
	// This is necessary because bytes address is
	// incremented after every memcpy.
	uint8_t *bytes_start = NULL;

	// This pointer points to the resulting hash.
	unsigned char *hash_result = NULL;

	// A temporare spki record 
	unsigned int router_keys_len;
	struct spki_record *tmp_key = NULL;
	int spki_count = 0;

	if (rtr_bgpsec_check_algorithm_suite(data->alg_suite_id) == BGPSEC_ERROR)
		return BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	
	// Make sure that all router keys are available.
	for (unsigned int i = 0; i < as_hops; i++) {
		retval = spki_table_search_by_ski(table, sig_segs[i].ski,
					 &tmp_key, &router_keys_len);
		if (retval == SPKI_ERROR)
			goto err;

		// Return an error, if a router key was not found.
		if (router_keys_len == 0) {
			char ski_str[(SKI_SIZE * 3) + 1] = {'\0'};
			_ski_to_char(&ski_str, sig_segs[i].ski);
			BGPSEC_DBG("ERROR: Could not find router key for SKI: %s",
				   ski_str);
			goto err;
		}
		lrtr_free(tmp_key);
	}

	_print_bgpsec_segment(&sig_segs[0], &sec_paths[0]);

	retval = _align_val_byte_sequence(data, sig_segs, sec_paths,
				          as_hops, &bytes, &bytes_len);

	if (retval == BGPSEC_ERROR)
		goto err;

	hash_result = lrtr_malloc(SHA256_DIGEST_LENGTH);
	if (hash_result == NULL)
		goto err;

	// Finished aligning the data.
	// Hashing begins here.
	
	int byte_sequence_offset = 0;
	for (int bytes_offset = 0, i = 0;
	     bytes_offset <= bytes_len && retval == BGPSEC_VALID;
	     bytes_offset += byte_sequence_offset, i++)
	{
		// sig_len + ski_size + sizeof(sig_segs[i].sig_len) + sec_path_seg_size 
		byte_sequence_offset = sig_segs[i].sig_len + SKI_SIZE + 2 + SECURE_PATH_SEGMENT_SIZE;
		if (data->alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
			printf("Byte Sequence:\n");
			_print_byte_sequence((const unsigned char *)&bytes[bytes_offset], (bytes_len - bytes_offset), 'v', 0);
			retval = _hash_byte_sequence((const unsigned char *)&bytes[bytes_offset],
						     (bytes_len - bytes_offset), hash_result);
			_print_byte_sequence(hash_result, SHA256_DIGEST_LENGTH, 'v', 0);
			printf("Hash:\n");
			_print_byte_sequence(hash_result, SHA256_DIGEST_LENGTH, 'v', 0);
		} else {
			retval = BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
			goto err;
		}

		if (retval == BGPSEC_ERROR)
			goto err;

		// Finished hashing.
		// Validation begins here.

		// Store all router keys for the given SKI in tmp_key.
		retval = spki_table_search_by_ski(table, sig_segs[i].ski,
						  &tmp_key, &router_keys_len);
		if (retval == SPKI_ERROR)
			goto err;

		// Loop in case there are multiple router keys for one SKI.
		int continue_loop = 1;
		for (unsigned int j = 0; j < router_keys_len && continue_loop; j++) {
			if (data->alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
				retval = _validate_signature(hash_result,
							     sig_segs[i].signature,
							     sig_segs[i].sig_len,
							     tmp_key[j].spki,
							     tmp_key[j].ski);
			} else {
				retval = BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
				goto err;
			}
			// As soon as one of the router keys produces a valid
			// result, exit the loop.
			if (retval == BGPSEC_VALID)
				continue_loop = 0;
		}
		lrtr_free(tmp_key);
	}
	if (bytes != NULL)
		lrtr_free(bytes);
	if (hash_result != NULL)
		lrtr_free(hash_result);

	if (retval == BGPSEC_VALID)
		BGPSEC_DBG1("Validation result for the whole BGPsec_PATH: valid");
	else
		BGPSEC_DBG1("Validation result for the whole BGPsec_PATH: invalid");

	return retval;

err:
	if (bytes != NULL)
		lrtr_free(bytes);
	if (tmp_key != NULL)
		lrtr_free(tmp_key);
	if (hash_result != NULL)
		lrtr_free(hash_result);

	return BGPSEC_ERROR;
}

int rtr_bgpsec_generate_signature(const struct bgpsec_data *data,
				  const struct signature_seg *sig_segs,
				  const struct secure_path_seg *sec_paths,
				  const struct spki_table *table,
				  const unsigned int as_hops,
				  const struct secure_path_seg *own_sec_path,
				  const unsigned int target_as,
				  char *private_key,
				  char *new_signature)
{
	// The return value. Holds the signature length
	// if successful.
	int retval;
	
	uint8_t *bytes = NULL;
	int bytes_len;

	// bytes_start holds the start address of bytes.
	// This is necessary because bytes address is
	// incremented after every memcpy.
	uint8_t *bytes_start = NULL;

	// This pointer points to the resulting hash.
	unsigned char *hash_result = NULL;

	// A temporare spki record 
	struct spki_record *tmp_key = NULL;
	int spki_count;

	if (rtr_bgpsec_check_algorithm_suite(data->alg_suite_id) == BGPSEC_ERROR)
		return BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	
	spki_count = 0;

	EC_KEY *priv_key = NULL;
	int priv_key_len = 0;

	retval = _load_private_key(&priv_key, private_key);

	if (retval != BGPSEC_SUCCESS) {
		retval = BGPSEC_LOAD_PRIV_KEY_ERROR;
		goto err;
	}

	retval = _align_gen_byte_sequence(data, sig_segs, sec_paths,
				          as_hops, own_sec_path, target_as,
				          &bytes, &bytes_len);

	if (retval == BGPSEC_ERROR) {
		goto err;
	}

	hash_result = lrtr_malloc(SHA256_DIGEST_LENGTH);
	if (hash_result == NULL) {
		retval = BGPSEC_ERROR;
		goto err;
	}
	
	if (data->alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
		_print_byte_sequence(bytes, bytes_len, 'v', 0);
		retval = _hash_byte_sequence((const unsigned char *)bytes,
					     bytes_len, hash_result);
		if (retval == BGPSEC_ERROR)
			goto err;
		_print_byte_sequence(hash_result, SHA256_DIGEST_LENGTH, 'v', 0);
	} else {
		retval = BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
		goto err;
	}

	/*_print_byte_sequence(hash_result, SHA256_DIGEST_LENGTH, 'v', 0);*/

	if (data->alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
		ECDSA_sign(0, hash_result, SHA256_DIGEST_LENGTH, new_signature,
			   &retval, priv_key);
		if (retval < 1)
			retval = BGPSEC_SIGN_ERROR;
	} else {
		retval = BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	}

	_print_byte_sequence(new_signature, retval, 'v', 0);

	lrtr_free(bytes);
	lrtr_free(hash_result);
	EC_KEY_free(priv_key);
	priv_key = NULL;

	return retval;

err:
	if (bytes_len > 0)
		lrtr_free(bytes);
	if (hash_result != NULL) 
		lrtr_free(hash_result);
	if (priv_key != NULL) 
		EC_KEY_free(priv_key);
	priv_key = NULL;

	return retval;
}


/*************************************************
 *********** Private helper functions ************
 ************************************************/

int _align_val_byte_sequence(const struct bgpsec_data *data,
			     const struct signature_seg *sig_segs,
			     const struct secure_path_seg *sec_paths,
			     const unsigned int as_hops,
			     uint8_t **bytes,
			     int *bytes_len)
{
	int sig_segs_size;
	uint32_t asn;
	uint16_t afi;

	uint8_t *bytes_start = NULL;

	// The size of all but the last appended Signature Segments
	// (which is the first element of the array).
	sig_segs_size = _get_sig_segs_size(sig_segs, as_hops, 1);

	// Calculate the total necessary size of bytes.
	// bgpsec_data struct in bytes is 4 + 1 + 2 + 1 + nlri_len
	*bytes_len = 8 + data->nlri_len +
			 sig_segs_size +
			 (SECURE_PATH_SEGMENT_SIZE * as_hops);

	*bytes = lrtr_malloc(*bytes_len);

	if (*bytes == NULL)
		return BGPSEC_ERROR;

	memset(*bytes, 0, *bytes_len);

	bytes_start = *bytes;

	// Begin here to align the byte sequence.

	asn = ntohl(data->asn);
	memcpy(*bytes, &asn, sizeof(asn));
	*bytes += sizeof(asn);

	for (unsigned int i = 0, j = 1; i < as_hops; i++, j++) {
		// Skip the first Signature Segment and go right to segment 1
		if (j < as_hops) {
			uint16_t sig_len = ntohs(sig_segs[j].sig_len);

			memcpy(*bytes, sig_segs[j].ski, SKI_SIZE);
			*bytes += SKI_SIZE;

			memcpy(*bytes, &sig_len, sizeof(sig_len));
			*bytes += sizeof(sig_len);

			memcpy(*bytes, sig_segs[j].signature,
			       sig_segs[j].sig_len);
			*bytes += sig_segs[j].sig_len;
		}

		// Secure Path Segment i
		memcpy(*bytes, &sec_paths[i].pcount, 1);
		*bytes += 1;

		memcpy(*bytes, &sec_paths[i].conf_seg, 1);
		*bytes += 1;

		asn = ntohl(sec_paths[i].asn);
		memcpy(*bytes, &asn, sizeof(asn));
		*bytes += sizeof(asn);
		/*_print_bgpsec_segment(&sig_segs[i], &sec_paths[i]);*/
	}

	// The rest of the BGPsec data.
	// The size of alg_suite_id + afi + safi.
	afi = ntohs(data->afi);
	memcpy(*bytes, &(data->alg_suite_id), 1);
	*bytes += 1;

	memcpy(*bytes, &afi, sizeof(afi));
	*bytes += sizeof(afi);

	memcpy(*bytes, (&data->safi), 1);
	*bytes += 1;

	// TODO: make trailing bits 0.
	memcpy(*bytes, data->nlri, data->nlri_len);

	// Set the pointer of bytes to the beginning.
	*bytes = bytes_start;

	/*_print_byte_sequence(*bytes, *bytes_len, 'v', 0);*/

	return BGPSEC_SUCCESS;
}

int _align_gen_byte_sequence(const struct bgpsec_data *data,
			     const struct signature_seg *sig_segs,
			     const struct secure_path_seg *sec_paths,
			     const unsigned int as_hops,
			     const struct secure_path_seg *own_sec_path,
			     const unsigned int target_as,
			     uint8_t **bytes,
			     int *bytes_len)
{
	int sig_segs_size;
	int sec_paths_len = as_hops + 1;
	uint32_t asn;
	uint16_t afi;

	struct secure_path_seg *all_sec_paths = NULL;
	uint8_t *bytes_start = NULL;
	// The size of all but the last appended Signature Segments
	// (which is the first element of the array).
	sig_segs_size = _get_sig_segs_size(sig_segs, as_hops, 0);

	all_sec_paths = lrtr_malloc(SECURE_PATH_SEGMENT_SIZE * sec_paths_len);

	if (all_sec_paths == NULL)
		return BGPSEC_ERROR;

	memcpy(all_sec_paths, own_sec_path, SECURE_PATH_SEGMENT_SIZE);
	memcpy(all_sec_paths + 1, sec_paths, SECURE_PATH_SEGMENT_SIZE * as_hops);

	// Calculate the total necessary size of bytes.
	// bgpsec_data struct in bytes is 4 + 1 + 2 + 1 + nlri_len
	*bytes_len = 8 + data->nlri_len +
			 sig_segs_size +
			 (SECURE_PATH_SEGMENT_SIZE * sec_paths_len);

	*bytes = lrtr_malloc(*bytes_len);

	if (*bytes == NULL) {
		lrtr_free(all_sec_paths);
		return BGPSEC_ERROR;
	}

	memset(*bytes, 0, *bytes_len);

	bytes_start = *bytes;

	// Begin here to align the byte sequence.

	asn = ntohl(target_as);
	memcpy(*bytes, &asn, sizeof(asn));
	*bytes += sizeof(asn);

	for (unsigned int i = 0; i < sec_paths_len; i++) {
		if (i < as_hops) {
			uint16_t sig_len = ntohs(sig_segs[i].sig_len);

			memcpy(*bytes, sig_segs[i].ski, SKI_SIZE);
			*bytes += SKI_SIZE;

			memcpy(*bytes, &sig_len, sizeof(sig_len));
			*bytes += sizeof(sig_len);

			memcpy(*bytes, sig_segs[i].signature,
			       sig_segs[i].sig_len);
			*bytes += sig_segs[i].sig_len;
		}

		// Secure Path Segment i
		memcpy(*bytes, &all_sec_paths[i].pcount, 1);
		*bytes += 1;

		memcpy(*bytes, &all_sec_paths[i].conf_seg, 1);
		*bytes += 1;

		asn = ntohl(all_sec_paths[i].asn);
		memcpy(*bytes, &asn, sizeof(asn));
		*bytes += sizeof(asn);
		/*_print_bgpsec_segment(&sig_segs[i], &sec_paths[i]);*/
	}

	// The rest of the BGPsec data.
	// The size of alg_suite_id + afi + safi.
	afi = ntohs(data->afi);
	memcpy(*bytes, &(data->alg_suite_id), 1);
	*bytes += 1;

	memcpy(*bytes, &afi, sizeof(afi));
	*bytes += sizeof(afi);

	memcpy(*bytes, (&data->safi), 1);
	*bytes += 1;
	// TODO: make trailing bits 0.
	memcpy(*bytes, data->nlri, data->nlri_len);

	// Set the pointer of bytes to the beginning.
	*bytes = bytes_start;

	lrtr_free(all_sec_paths);

	/*_print_byte_sequence(*bytes, *bytes_len, 'v', 0);*/

	return BGPSEC_SUCCESS;
}

int _validate_signature(const unsigned char *hash,
			uint8_t *signature,
			uint16_t sig_len,
			uint8_t *spki,
			uint8_t *ski)
{
	int status;
	int retval = BGPSEC_ERROR;

	EC_KEY *pub_key = NULL;

	retval = _load_public_key(&pub_key, spki);
	if (retval != BGPSEC_SUCCESS) {
		char ski_str[(SKI_SIZE * 3) + 1] = {'\0'};
		_ski_to_char(&ski_str, ski);
		BGPSEC_DBG("WARNING: Invalid public key for SKI: %s", ski_str);
		retval = BGPSEC_ERROR;
		goto err;
	}

	status = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, pub_key);

	switch(status) {
	case -1:
		BGPSEC_DBG1("ERROR: Failed to verify EC Signature");
		retval = BGPSEC_ERROR;
		break;
	case 0:
		retval = BGPSEC_NOT_VALID;
		BGPSEC_DBG1("Validation result of signature: invalid");
		break;
	case 1:
		retval = BGPSEC_VALID;
		BGPSEC_DBG1("Validation result of signature: valid");
		break;
	}

	EC_KEY_free(pub_key);

err:
	return retval;
}

int _load_public_key(EC_KEY **pub_key, uint8_t *spki)
{
	int status;
	char *p = (char *)spki;
	*pub_key = NULL;
	size_t pub_key_int;

	pub_key_int = (size_t)d2i_EC_PUBKEY(NULL, (const unsigned char **)&p,
					    (long)SPKI_SIZE);

	if (pub_key_int == NULL)
		return BGPSEC_LOAD_PUB_KEY_ERROR;

	*pub_key = (EC_KEY*)pub_key_int;

	if (*pub_key == NULL)
		return BGPSEC_LOAD_PUB_KEY_ERROR;

	status = EC_KEY_check_key(*pub_key);
	if (status == 0) {
		EC_KEY_free(*pub_key);
		*pub_key = NULL;
		return BGPSEC_LOAD_PUB_KEY_ERROR;
	}

	return BGPSEC_SUCCESS;
}

int _load_private_key(EC_KEY **priv_key, uint8_t *bytes_key)
{
	int status;
	char *p = (char *)bytes_key;
	*priv_key = NULL;

	*priv_key = d2i_ECPrivateKey(NULL, (const unsigned char **)&p,
				     (long)PRIVATE_KEY_LENGTH);

	if (*priv_key == NULL)
		return BGPSEC_LOAD_PRIV_KEY_ERROR;

	status = EC_KEY_check_key(*priv_key);
	if (status == 0) {
		EC_KEY_free(*priv_key);
		*priv_key = NULL;
		return BGPSEC_LOAD_PRIV_KEY_ERROR;
	}

	return BGPSEC_SUCCESS;
}

int _get_sig_segs_size(const struct signature_seg *sig_segs,
		       const unsigned int sig_segs_len,
		       const unsigned int offset)
{
	int sig_segs_size = 0;
	if (sig_segs_len > 0) {
		for (int i = offset; i < sig_segs_len; i++) {
			sig_segs_size += sig_segs[i].sig_len +
					 sizeof(sig_segs[i].sig_len) +
					 SKI_SIZE;
		}
	}
	return sig_segs_size;
}

/*************************************************
 **** Functions for versions and algo suites *****
 ************************************************/

int rtr_bgpsec_get_version()
{
	return BGPSEC_VERSION;
}

int rtr_bgpsec_check_algorithm_suite(int alg_suite)
{
	if (alg_suite == BGPSEC_ALGORITHM_SUITE_1)
		return BGPSEC_SUCCESS;
	else
		return BGPSEC_ERROR;
}

int rtr_bgpsec_get_algorithm_suites_arr(int **algs_arr)
{
	*algs_arr = &algorithm_suites;
	return ALGORITHM_SUITES_COUNT;
}

int _hash_byte_sequence(const unsigned char *bytes,
			unsigned int bytes_len,
			const unsigned char *hash_result)
{
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, bytes, bytes_len);
	SHA256_Final(hash_result, &ctx);

	if (hash_result == NULL)
		return BGPSEC_ERROR;

	return BGPSEC_SUCCESS;
}

/*************************************************
 ******** Functions for pretty printing **********
 ************************************************/

void _print_byte_sequence(const unsigned char *bytes,
			  unsigned int bytes_size,
			  char alignment,
			  int tabstops)
{
	int bytes_printed = 1;
	switch (alignment) {
	case 'h':
		for (unsigned int i = 0; i < bytes_size; i++)
			printf("Byte %d/%d: %02X\n", i+1, bytes_size, bytes[i]);
		break;
	case 'v':
	default:
		for (int j = 0; j < tabstops; j++)
			printf("\t");
		for (unsigned int i = 0; i < bytes_size; i++, bytes_printed++) {
			printf("%02X ", bytes[i]);

			// Only print 16 bytes in a single line.
			if (bytes_printed % 16 == 0) {
				printf("\n");
				for (int j = 0; j < tabstops; j++)
					printf("\t");
			}
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

void _print_bgpsec_segment(struct signature_seg *sig_seg,
			   struct secure_path_seg *sec_path)
{
	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	printf("Signature Segment:\n");
	printf("\tSKI:\n");
	_print_byte_sequence(sig_seg->ski, SKI_SIZE, "v", 2);
	printf("\tLength: %d\n", sig_seg->sig_len);
	printf("\tSignature:\n");
	_print_byte_sequence(sig_seg->signature, sig_seg->sig_len, "v", 2);
	printf("---------------------------------------------------------------\n");
	printf("Secure_Path Segment:\n\
			\tpCount: %d\n\
			\tFlags: %d\n\
			\tAS number: %d\n",
			sec_path->pcount,
			sec_path->conf_seg,
			sec_path->asn);
	printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	printf("\n");
}

void _ski_to_char(unsigned char *ski_str, uint8_t *ski)
{
	for (int i = 0; i < SKI_SIZE; i++)
		sprintf(&ski_str[i*3], "%02X ", (unsigned char)ski[i]);
}
