/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#ifndef BGPSEC_H
#define BGPSEC_H

#include <openssl/x509.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "rtrlib/spki/hashtable/ht-spkitable.h"

#define BGPSEC_VERSION			0
#define BGPSEC_ALGORITHM_SUITE_1	1
#define ALGORITHM_SUITES_COUNT		1

#define SECURE_PATH_SEGMENT_SIZE	6

#define SIG_LEN_SIZE			2
#define ASN_SIZE			4

#define BYTE_SEQUENCE_OFFSET		100

enum bgpsec_rtvals {
	BGPSEC_SUCCESS = 0,
	BGPSEC_ERROR = -1,
	BGPSEC_LOAD_PUB_KEY_ERROR = -2,
	BGPSEC_LOAD_PRIV_KEY_ERROR = -3,
	BGPSEC_ROUTER_KEY_NOT_FOUND = -4,
	BGPSEC_SIGN_ERROR = -5,
};

/**
 * @brief Validation result of an AS path validation.
 */
enum bgpsec_result {
	/** All signatures are valid. */
	BGPSEC_VALID = 0,
	/** At least one signature is not valid. */
	BGPSEC_NOT_VALID = 1,
};

/**
 * @brief A single Secure_Path Segment.
 * @param pcount The pCount field of the segment.
 * @param conf_seg The Confed Segment flag of the segment.
 * @param asn The ASN of the Segment.
 */
struct secure_path_seg {
	uint8_t pcount;
	uint8_t conf_seg;
	uint32_t asn;
} __attribute__((packed));

/**
 * @brief A single Signature Segment.
 * @param ski The SKI of the segment.
 * @param sig_len The length in octets of the signature field.
 * @param signature The signature of the segment.
 */
struct signature_seg {
	uint8_t *ski;
	uint16_t sig_len;
	uint8_t *signature;
} __attribute__((packed));

/**
 * @brief The data that is passed to the bgpsec_validate_as_path function.
 * @param alg_suite_id The identifier, which algorithm suite must be used.
 * @param afi The Address Family Identifier.
 * @param safi The Subsequent Address Family Identifier.
 * @param nlri The Network Layer Reachability Information.
 * @param nlri_len The length of nlri in bytes.
 */
struct bgpsec_data {
	uint8_t alg_suite_id;
	uint16_t afi;
	uint8_t safi;
	uint32_t asn;
	uint8_t *nlri;
	uint16_t nlri_len;
} __attribute__((packed));

/**
 * @brief Validation function for AS path validation.
 * @param[in] data Data required for AS path validation.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update.
 * @param[in] as_hops The amount of AS hops the update has taken.
 * @return BGPSEC_VALID If the AS path was valid.
 * @return BGPSEC_NOT_VALID If the AS path was not valid.
 * @return RTR_BGPSEC_ERROR If an error occurred.
 */
int bgpsec_validate_as_path(struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    struct spki_table *table,
			    const unsigned int as_hops);

int bgpsec_create_signature(struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    struct spki_table *table,
			    const unsigned int as_hops,
			    char *ski,
			    char *new_signature);

int bgpsec_get_version();

int bgpsec_check_algorithm_suite(int alg_suite);

int bgpsec_get_algorithm_suites_arr(char *algs_arr);

#endif
