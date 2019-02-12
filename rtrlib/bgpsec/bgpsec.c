/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include <openssl/x509.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "rtrlib/bgpsec/bgpsec.h"
#include "rtrlib/lib/log.h"
#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/rtrlib_export_private.h"
#include "rtrlib/spki/spkitable_private.h"

#define BGPSEC_DBG(fmt, ...) lrtr_dbg("BGPSEC: " fmt, ## __VA_ARGS__)
#define BGPSEC_DBG1(a) lrtr_dbg("BGPSEC: " a)

/** The latest supported BGPsec version. */
#define BGPSEC_VERSION 0

/** The string length of a SKI, including spaces. */
#define SKI_STR_LEN 61

/** The total length of a private key in bytes. */
#define PRIVATE_KEY_LENGTH 121L

/**
 * @brief A static list that contains all supported algorithm suites.
 */
static const uint8_t algorithm_suites[] = {
	BGPSEC_ALGORITHM_SUITE_1
};

static int align_val_byte_sequence(
		const struct rtr_bgpsec_data *data,
		const struct rtr_signature_seg *sig_segs,
		const struct rtr_secure_path_seg *sec_paths,
		const unsigned int as_hops,
		uint8_t **bytes,
		unsigned int *bytes_len);

static int align_gen_byte_sequence(
		const struct rtr_bgpsec_data *data,
		const struct rtr_signature_seg *sig_segs,
		const struct rtr_secure_path_seg *sec_paths,
		const unsigned int as_hops,
		const struct rtr_secure_path_seg *own_sec_path,
		const unsigned int target_as,
		uint8_t **bytes,
		unsigned int *bytes_len);

static int hash_byte_sequence(
		uint8_t *bytes,
		unsigned int bytes_len,
		uint8_t alg_suite_id,
		unsigned char *result_buffer);

static int validate_signature(
		const unsigned char *hash,
		uint8_t *signature,
		uint16_t sig_len,
		uint8_t *spki,
		uint8_t *ski);

static int get_sig_seg_size(
		const struct rtr_signature_seg *sig_segs,
		const unsigned int sig_segs_len,
		const unsigned int offset);

static int bgpsec_segment_to_str(
		char *buffer,
		const struct rtr_signature_seg *sig_seg,
		const struct rtr_secure_path_seg *sec_path);

static int byte_sequence_to_str(
		char *buffer,
		const unsigned char *bytes,
		unsigned int bytes_size,
		unsigned int tabstops);

static void ski_to_char(char *ski_str, uint8_t *ski);

static int load_private_key(EC_KEY **priv_key, uint8_t *bytes_key);

static int load_public_key(EC_KEY **pub_key, uint8_t *spki);

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

RTRLIB_EXPORT int rtr_bgpsec_validate_as_path(
				const struct rtr_bgpsec_data *data,
				const struct rtr_signature_seg *sig_segs,
				const struct rtr_secure_path_seg *sec_paths,
				struct spki_table *table,
				const unsigned int as_hops)
{
	/* The AS path validation result. */
	enum rtr_bgpsec_rtvals retval = 0;

	/* bytes holds the byte sequence that is hashed. */
	uint8_t *bytes = NULL;
	unsigned int bytes_len = 0;

	/* This pointer points to the resulting hash. */
	unsigned char *hash_result = NULL;

	/* A temporare spki record */
	struct spki_record *tmp_key = NULL;

	/* Check, if the parameters are not NULL */
	if (!data || !sig_segs || !sec_paths || !table)
		return BGPSEC_ERROR;

	/* Check if there has been at least one hop */
	if (as_hops < 1)
		return BGPSEC_ERROR;

	/* Check, if the algorithm suite is supported by RTRlib. */
	if (rtr_bgpsec_check_algorithm_suite(data->alg_suite_id) ==
			BGPSEC_ERROR) {
		return BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	}

	/* Make sure that all router keys are available. */
	for (unsigned int i = 0; i < as_hops; i++) {
		unsigned int router_keys_len = 0;
		enum spki_rtvals spki_retval = spki_table_search_by_ski(
							table,
							sig_segs[i].ski,
							&tmp_key,
							&router_keys_len);
		if (spki_retval == SPKI_ERROR)
			goto err;

		/* Return an error, if a router key was not found. */
		if (router_keys_len == 0) {
			char ski_str[SKI_STR_LEN] = {'\0'};

			ski_to_char(ski_str, sig_segs[i].ski);
			BGPSEC_DBG(
				"ERROR: Could not find router key for SKI: %s",
				ski_str);
			goto err;
		}
		lrtr_free(tmp_key);
	}

	retval = align_val_byte_sequence(data, sig_segs, sec_paths,
					 as_hops, &bytes, &bytes_len);

	if (retval == BGPSEC_ERROR)
		goto err;

	hash_result = lrtr_malloc(SHA256_DIGEST_LENGTH);
	if (!hash_result)
		goto err;

	/*
	 * offset: the current position from where bytes should
	 * be processed.
	 *
	 * next_offset: adds to offset, after the bytes on the
	 * current offset have been processed. next_offset is not
	 * constant and must be calculated each iteration:
	 *
	 * signature length +
	 * SKI size +
	 * sizeof(var that holds signature length) +
	 * sizeof(a secure path segment)
	 *
	 *
	 *  offset
	 * |o----------------------------------------| bytes
	 *
	 *		offset+=
	 *		new_offset
	 * |++++++++++++o----------------------------| bytes
	 *
	 *			    offset+=
	 *			    new_offset
	 * |++++++++++++++++++++++++o----------------| bytes
	 *
	 *
	 * A more detailed view can be found at
	 * https://mailarchive.ietf.org/arch/msg/sidr/8B_e4CNxQCUKeZ_AUzsdnn2f5Mu
	 **/

	/* Set retval to BGPSEC_VALID so the for-condition does not
	 * fail on the first time checking.
	 */
	retval = BGPSEC_VALID;

	for (unsigned int i = 0, offset = 0, next_offset = 0;
	     offset <= bytes_len && retval == BGPSEC_VALID;
	     offset += next_offset, i++) {
		next_offset =	sig_segs[i].sig_len +
				SKI_SIZE +
				sizeof(sig_segs[i].sig_len) +
				sizeof(struct rtr_secure_path_seg);

		/* Hash the bytes from the offset position out. */
		retval = hash_byte_sequence(&bytes[offset],
					    (bytes_len - offset),
					    data->alg_suite_id,
					    hash_result);

		if (retval != BGPSEC_SUCCESS)
			goto err;

		/* Store all router keys for the given SKI in tmp_key. */
		unsigned int router_keys_len = 0;
		enum spki_rtvals spki_retval = spki_table_search_by_ski(
							table,
							sig_segs[i].ski,
							&tmp_key,
							&router_keys_len);
		if (spki_retval == SPKI_ERROR)
			goto err;

		/* Return an error, if a router key was not found. */
		if (router_keys_len == 0) {
			char ski_str[SKI_STR_LEN] = {'\0'};

			ski_to_char(ski_str, sig_segs[i].ski);
			BGPSEC_DBG(
				"ERROR: Could not find router key for SKI: %s",
				ski_str);
			goto err;
		}

		unsigned int continue_loop = 1;

		/* Loop in case there are multiple router keys for one SKI. */
		for (unsigned int j = 0;
		     j < router_keys_len && continue_loop;
		     j++) {
			/* Validate the siganture depending on the algorithm
			 * suite. More if-cases are added with new algorithm
			 * suites.
			 */
			if (data->alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
				retval = validate_signature(
						hash_result,
						sig_segs[i].signature,
						sig_segs[i].sig_len,
						tmp_key[j].spki,
						tmp_key[j].ski);
			} else {
				retval = BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
				goto err;
			}
			/* As soon as one of the router keys produces a valid
			 * result, exit the loop.
			 */
			if (retval == BGPSEC_VALID)
				continue_loop = 0;
		}
		lrtr_free(tmp_key);
	}

	if (bytes)
		lrtr_free(bytes);
	if (hash_result)
		lrtr_free(hash_result);

	if (retval == BGPSEC_VALID)
		BGPSEC_DBG1(
			"Validation result for the whole BGPsec_PATH: valid");
	else
		BGPSEC_DBG1(
			"Validation result for the whole BGPsec_PATH: invalid");

	return retval;

err:
	if (bytes)
		lrtr_free(bytes);
	if (tmp_key)
		lrtr_free(tmp_key);
	if (hash_result)
		lrtr_free(hash_result);

	return BGPSEC_ERROR;
}

RTRLIB_EXPORT int rtr_bgpsec_generate_signature(
				  const struct rtr_bgpsec_data *data,
				  const struct rtr_signature_seg *sig_segs,
				  const struct rtr_secure_path_seg *sec_paths,
				  const unsigned int as_hops,
				  const struct rtr_secure_path_seg *own_sec_path,
				  const unsigned int target_as,
				  uint8_t *private_key,
				  uint8_t *new_signature)
{
	/* The return value. Holds the signature length
	 * if signing was successful.
	 */
	int retval = 0;

	/* Holds the aligned bytes. */
	uint8_t *bytes = NULL;
	unsigned int bytes_len = 0;

	/* The resulting hash. */
	unsigned char *hash_result = NULL;

	/* OpenSSL private key structure. */
	EC_KEY *priv_key = NULL;

	/* Check, if the parameters are not NULL */
	if (!data || !own_sec_path || !private_key)
		return BGPSEC_ERROR;

	/* Make sure the algorithm suite is supported. */
	if (rtr_bgpsec_check_algorithm_suite(data->alg_suite_id) ==
			BGPSEC_ERROR) {
		return BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	}

	/* Load the private key from buffer into OpenSSL structure. */
	retval = load_private_key(&priv_key, private_key);

	if (retval != BGPSEC_SUCCESS) {
		retval = BGPSEC_LOAD_PRIV_KEY_ERROR;
		goto err;
	}

	/* Align the bytes to prepare them for hashing. */
	retval = align_gen_byte_sequence(data, sig_segs, sec_paths,
					 as_hops, own_sec_path, target_as,
					 &bytes, &bytes_len);

	if (retval == BGPSEC_ERROR)
		goto err;

	hash_result = lrtr_malloc(SHA256_DIGEST_LENGTH);
	if (!hash_result) {
		retval = BGPSEC_ERROR;
		goto err;
	}

	/* Hash the aligned bytes. */
	retval = hash_byte_sequence(bytes, bytes_len,
				    data->alg_suite_id,
				    hash_result);

	if (retval != BGPSEC_SUCCESS)
		goto err;

	/* Sign the hash depending on the algorithm suite. */
	if (data->alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
		ECDSA_sign(0, hash_result, SHA256_DIGEST_LENGTH, new_signature,
			   &retval, priv_key);
		if (retval < 1)
			retval = BGPSEC_SIGNING_ERROR;
	} else {
		retval = BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	}

	lrtr_free(bytes);
	lrtr_free(hash_result);
	EC_KEY_free(priv_key);
	priv_key = NULL;

	return retval;

err:
	if (bytes_len > 0)
		lrtr_free(bytes);
	if (hash_result)
		lrtr_free(hash_result);
	if (priv_key)
		EC_KEY_free(priv_key);
	priv_key = NULL;

	return retval;
}

/*************************************************
 *********** Private helper functions ************
 ************************************************/

static int align_val_byte_sequence(
		const struct rtr_bgpsec_data *data,
		const struct rtr_signature_seg *sig_segs,
		const struct rtr_secure_path_seg *sec_paths,
		const unsigned int as_hops,
		uint8_t **bytes,
		unsigned int *bytes_len)
{
	unsigned int sig_segs_size = 0;
	uint32_t asn = 0;
	uint16_t afi = 0;

	/* bytes_start holds the start address of bytes.
	 * This is necessary because bytes address is
	 * incremented after every memcpy.
	 */
	uint8_t *bytes_start = NULL;

	/*
	 * Before allocating space for bytes, we must determine just
	 * how much space we need. bytes requires space for the size
	 * of all signature segments, all secure_path segments, the
	 * NLRI size and the rest of the BGPsec information (AFI,
	 * SAFI, ASN, algorithm suite).
	 * While information like the secure_path segments and BGPsec
	 * information are of static size, the signature segments are
	 * of dynamic size and must be calculated one by one.
	 * In the end, all sizes are added and stored into bytes_len
	 * for memory allocation for bytes.
	 */

	/* Get the size of all but the last appended signature segments
	 * (which is the first element of the array). The last appended
	 * signature segment is the segment that is currently validated,
	 * therefore it must not be part of the hashing.
	 */
	sig_segs_size = get_sig_seg_size(sig_segs, as_hops, 1);

	/* Calculate the total necessary size of bytes.
	 * rtr_bgpsec_data struct in bytes is 1 + 1 + 2 + 4 + nlri_len
	 */
	*bytes_len = 8 + data->nlri_len +
			 sig_segs_size +
			 (sizeof(struct rtr_secure_path_seg) * as_hops);

	*bytes = lrtr_malloc(*bytes_len);

	if (!*bytes)
		return BGPSEC_ERROR;

	memset(*bytes, 0, *bytes_len);

	/* Store the start position of bytes to reset the position
	 * to the beginning later.
	 */
	bytes_start = *bytes;

	/* The data alignment begins here, starting with the target ASN. */
	asn = ntohl(data->asn);
	memcpy(*bytes, &asn, sizeof(asn));
	*bytes += sizeof(asn);

	/* Now, all signature segments (if any) and all secure_path segments
	 * are copied to bytes.
	 */
	for (unsigned int i = 0, j = 1; i < as_hops; i++, j++) {
		/* Skip the first Signature Segment and go right to segment 1 */
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

		/* Secure Path Segment i */
		memcpy(*bytes, &sec_paths[i].pcount, 1);
		*bytes += 1;

		memcpy(*bytes, &sec_paths[i].conf_seg, 1);
		*bytes += 1;

		asn = ntohl(sec_paths[i].asn);
		memcpy(*bytes, &asn, sizeof(asn));
		*bytes += sizeof(asn);
	}

	/* The rest of the BGPsec data.
	 * The size of alg_suite_id + afi + safi.
	 */
	memcpy(*bytes, &data->alg_suite_id, 1);
	*bytes += 1;

	afi = ntohs(data->afi);
	memcpy(*bytes, &afi, sizeof(afi));
	*bytes += sizeof(afi);

	memcpy(*bytes, (&data->safi), 1);
	*bytes += 1;

	memcpy(*bytes, data->nlri, data->nlri_len);

	/* Set the pointer of bytes to the beginning. */
	*bytes = bytes_start;

	/*byte_sequence_to_str(*bytes, *bytes_len, 0);*/

	return BGPSEC_SUCCESS;
}

static int align_gen_byte_sequence(
		const struct rtr_bgpsec_data *data,
		const struct rtr_signature_seg *sig_segs,
		const struct rtr_secure_path_seg *sec_paths,
		const unsigned int as_hops,
		const struct rtr_secure_path_seg *own_sec_path,
		const unsigned int target_as,
		uint8_t **bytes,
		unsigned int *bytes_len)
{
	unsigned int sig_segs_size = 0;
	uint32_t asn = 0;
	uint16_t afi = 0;

	/* sec_paths_len is the amount of all sec_paths + the
	 * own_sec_path.
	 */
	unsigned int sec_paths_len = as_hops + 1;

	/* Since there are both the sec_paths as well as the
	 * own_sec_path, the two have to be merged together in
	 * all_sec_paths. This makes further processing easier.
	 */
	struct rtr_secure_path_seg *all_sec_paths = NULL;

	/* bytes_start holds the start address of bytes.
	 * This is necessary because bytes address is
	 * incremented after every memcpy.
	 */
	uint8_t *bytes_start = NULL;

	/* Allocate space for the sec_paths + the own_sec_path.
	 * Since they are of static size, this is sufficient.
	 */
	int tmp_size = sizeof(struct rtr_secure_path_seg) * sec_paths_len;

	all_sec_paths = lrtr_malloc(tmp_size);

	if (!all_sec_paths)
		return BGPSEC_ERROR;

	/* Copy the own_sec_path at the beginning of all_sec_paths.
	 * Add 2 to sizeof(struct rtr_secure_path_seg) to consider padding in struct.
	 */
	memcpy(all_sec_paths, own_sec_path, sizeof(struct rtr_secure_path_seg));

	/* Copy the remaining sec_paths to all_sec_paths with an
	 * offset of 1 (the own_sec_path).
	 */
	memcpy(all_sec_paths + 1, sec_paths,
	       sizeof(struct rtr_secure_path_seg) * as_hops);

	/* Get the signature segments size just like in
	 * align_val_byte_sequence, except this time there is
	 * no offset by one segment. This time, the hash needs
	 * to include all signature segments.
	 */
	sig_segs_size = get_sig_seg_size(sig_segs, as_hops, 0);

	/* Calculate the total necessary size of bytes.
	 * rtr_bgpsec_data struct in bytes is 1 + 1 + 2 + 4 + nlri_len
	 */
	*bytes_len = 8 + data->nlri_len +
			 sig_segs_size +
			 (sizeof(struct rtr_secure_path_seg) * sec_paths_len);

	*bytes = lrtr_malloc(*bytes_len);

	if (!*bytes) {
		lrtr_free(all_sec_paths);
		return BGPSEC_ERROR;
	}

	memset(*bytes, 0, *bytes_len);

	bytes_start = *bytes;

	/* Begin here to align the byte sequence. */

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

		/* Secure Path Segment i */
		memcpy(*bytes, &all_sec_paths[i].pcount, 1);
		*bytes += 1;

		memcpy(*bytes, &all_sec_paths[i].conf_seg, 1);
		*bytes += 1;

		asn = ntohl(all_sec_paths[i].asn);
		memcpy(*bytes, &asn, sizeof(asn));
		*bytes += sizeof(asn);
	}

	/* The rest of the BGPsec data.
	 * The size of alg_suite_id + afi + safi.
	 */
	memcpy(*bytes, &data->alg_suite_id, 1);
	*bytes += 1;

	afi = ntohs(data->afi);
	memcpy(*bytes, &afi, sizeof(afi));
	*bytes += sizeof(afi);

	memcpy(*bytes, (&data->safi), 1);
	*bytes += 1;

	memcpy(*bytes, data->nlri, data->nlri_len);

	/* Set the pointer of bytes to the beginning. */
	*bytes = bytes_start;

	lrtr_free(all_sec_paths);

	return BGPSEC_SUCCESS;
}

static int validate_signature(
		const unsigned char *hash,
		uint8_t *signature,
		uint16_t sig_len,
		uint8_t *spki,
		uint8_t *ski)
{
	int status = 0;
	enum rtr_bgpsec_rtvals retval = BGPSEC_ERROR;

	EC_KEY *pub_key = NULL;

	/* Load the contents of the spki buffer into the
	 * OpenSSL public key.
	 */
	retval = load_public_key(&pub_key, spki);

	if (retval != BGPSEC_SUCCESS) {
		char ski_str[(SKI_SIZE * 3) + 1] = {'\0'};

		ski_to_char(ski_str, ski);
		BGPSEC_DBG("WARNING: Invalid public key for SKI: %s", ski_str);
		retval = BGPSEC_ERROR;
		goto err;
	}

	/* The OpenSSL validation function to validate the signature. */
	status = ECDSA_verify(
			0,
			hash,
			SHA256_DIGEST_LENGTH,
			signature,
			sig_len,
			pub_key);

	switch (status) {
	case -1:
		BGPSEC_DBG1("ERROR: Failed to verify EC Signature");
		retval = BGPSEC_ERROR;
		break;
	case 0:
		BGPSEC_DBG1("Validation result of signature: invalid");
		retval = BGPSEC_NOT_VALID;
		break;
	case 1:
		BGPSEC_DBG1("Validation result of signature: valid");
		retval = BGPSEC_VALID;
		break;
	}

	EC_KEY_free(pub_key);

err:
	return retval;
}

static int load_public_key(EC_KEY **pub_key, uint8_t *spki)
{
	int status = 0;
	char *p = (char *)spki;
	*pub_key = NULL;
	size_t pub_key_int = 0;

	/* This whole procedure is one way to copy the spki into
	 * an EC_KEY, suggested by OpenSSL. Basically, this function
	 * returns the public key as a long int, which can later be
	 * casted to an EC_KEY
	 */
	pub_key_int = (size_t)d2i_EC_PUBKEY(NULL, (const unsigned char **)&p,
					    (long)SPKI_SIZE);

	if (!pub_key_int)
		return BGPSEC_LOAD_PUB_KEY_ERROR;

	*pub_key = (EC_KEY *)pub_key_int;

	if (!*pub_key)
		return BGPSEC_LOAD_PUB_KEY_ERROR;

	status = EC_KEY_check_key(*pub_key);
	if (status == 0) {
		EC_KEY_free(*pub_key);
		*pub_key = NULL;
		return BGPSEC_LOAD_PUB_KEY_ERROR;
	}

	return BGPSEC_SUCCESS;
}

static int load_private_key(EC_KEY **priv_key, uint8_t *bytes_key)
{
	int status = 0;
	char *p = (char *)bytes_key;
	*priv_key = NULL;

	/* The private key copying is similar to the public key
	 * copying, except that the private key is returned directly
	 * as an EC_KEY.
	 */
	*priv_key = d2i_ECPrivateKey(NULL, (const unsigned char **)&p,
				     (long)PRIVATE_KEY_LENGTH);

	if (!*priv_key)
		return BGPSEC_LOAD_PRIV_KEY_ERROR;

	status = EC_KEY_check_key(*priv_key);
	if (status == 0) {
		EC_KEY_free(*priv_key);
		*priv_key = NULL;
		return BGPSEC_LOAD_PRIV_KEY_ERROR;
	}

	return BGPSEC_SUCCESS;
}

static int get_sig_seg_size(
		const struct rtr_signature_seg *sig_segs,
		const unsigned int sig_segs_len,
		const unsigned int offset)
{
	unsigned int sig_segs_size = 0;

	/* Iterate over all signature segments and add the calculated
	 * length to sig_segs_size. Return the sum at the end.
	 */
	if (sig_segs_len > 0) {
		for (unsigned int i = offset; i < sig_segs_len; i++) {
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

RTRLIB_EXPORT int rtr_bgpsec_get_version(void)
{
	return BGPSEC_VERSION;
}

RTRLIB_EXPORT int rtr_bgpsec_check_algorithm_suite(unsigned int alg_suite)
{
	int alg_suites_len = sizeof(algorithm_suites) / sizeof(uint8_t);

	for (int i = 0; i < alg_suites_len; i++) {
		if (alg_suite == algorithm_suites[i])
			return BGPSEC_SUCCESS;
	}

	return BGPSEC_ERROR;
}

RTRLIB_EXPORT int rtr_bgpsec_get_algorithm_suites_arr(const uint8_t **algs_arr)
{
	*algs_arr = algorithm_suites;
	return sizeof(algorithm_suites) / sizeof(uint8_t);
}

static int hash_byte_sequence(
		uint8_t *bytes,
		unsigned int bytes_len,
		uint8_t alg_suite_id,
		unsigned char *hash_result)
{
	if (alg_suite_id == BGPSEC_ALGORITHM_SUITE_1) {
		SHA256_CTX ctx;

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (const unsigned char *)bytes, bytes_len);
		SHA256_Final(hash_result, &ctx);

		if (!hash_result)
			return BGPSEC_ERROR;
	} else {
		return BGPSEC_UNSUPPORTED_ALGORITHM_SUITE;
	}

	return BGPSEC_SUCCESS;
}

/*************************************************
 ******** Functions for pretty printing **********
 ************************************************/

static int byte_sequence_to_str(
		char *buffer,
		const unsigned char *bytes,
		unsigned int bytes_size,
		unsigned int tabstops)
{
	unsigned int bytes_printed = 1;

	for (unsigned int j = 0; j < tabstops; j++)
		buffer += sprintf(buffer, "\t");

	for (unsigned int i = 0; i < bytes_size; i++, bytes_printed++) {
		buffer += sprintf(buffer, "%02X ", bytes[i]);

		/* Only print 16 bytes in a single line. */
		if (bytes_printed % 16 == 0) {
			buffer += sprintf(buffer, "\n");
			for (unsigned int j = 0; j < tabstops; j++)
				buffer += sprintf(buffer, "\t");
		}
	}

	/* TODO: that's ugly.
	 * If there was no new line printed at the end of the for loop,
	 * print an extra new line.
	 */
	if (bytes_size % 16 != 0)
		buffer += sprintf(buffer, "\n");
	sprintf(buffer, "\n");
	return BGPSEC_SUCCESS;
}

static int bgpsec_segment_to_str(
		char *buffer,
		const struct rtr_signature_seg *sig_seg,
		const struct rtr_secure_path_seg *sec_path)
{
	char byte_buffer[256] = {'\0'};

	buffer += sprintf(buffer, "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	buffer += sprintf(buffer, "Signature Segment:\n");
	buffer += sprintf(buffer, "\tSKI:\n");

	byte_sequence_to_str(byte_buffer, sig_seg->ski, SKI_SIZE, 2);
	buffer += sprintf(buffer, "%s\n", byte_buffer);

	buffer += sprintf(buffer, "\tLength: %d\n", sig_seg->sig_len);
	buffer += sprintf(buffer, "\tSignature:\n");

	memset(byte_buffer, 0, sizeof(byte_buffer));
	byte_sequence_to_str(byte_buffer, sig_seg->signature, sig_seg->sig_len,
			     2);
	buffer += sprintf(buffer, "%s\n", byte_buffer);

	buffer += sprintf(buffer, "---------------------------------------------------------------\n");
	buffer += sprintf(buffer, "Secure_Path Segment:\n"
			"\tpCount: %d\n"
			"\tFlags: %d\n"
			"\tAS number: %d\n",
			sec_path->pcount,
			sec_path->conf_seg,
			sec_path->asn);
	buffer += sprintf(buffer, "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
	buffer += sprintf(buffer, "\n");
	*buffer = '\0';

	return BGPSEC_SUCCESS;
}

static void ski_to_char(char *ski_str, uint8_t *ski)
{
	for (unsigned int i = 0; i < SKI_SIZE; i++)
		sprintf(&ski_str[i * 3], "%02X ", ski[i]);
}
