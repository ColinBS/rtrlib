/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

/**
 * @defgroup mod_bgpsec_h BGPsec AS path validation @brief BGPsec allows for
 * validation of the BGPsec_PATH attribute of a BGPsec update.
 * @{
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

#define PUBLIC_KEY_LENGTH		65
#define SPKI_HEADER_LENGTH		26
#define PRIVATE_KEY_LENGTH		121

/**
 * @brief Status codes for various cases.
 */
enum bgpsec_rtvals {
	/** An operation was successful. */
	BGPSEC_SUCCESS = 0,
	/** An operation was not sucessful. */
	BGPSEC_ERROR = -1,
	/** The public key could not be loaded. */
	BGPSEC_LOAD_PUB_KEY_ERROR = -2,
	/** The private key could not be loaded. */
	BGPSEC_LOAD_PRIV_KEY_ERROR = -3,
	/** The SKI for a router key was not found. */
	BGPSEC_ROUTER_KEY_NOT_FOUND = -4,
	/** An error during signing occurred. */
	BGPSEC_SIGN_ERROR = -5,
	/** The specified algorithm suite is not supported by RTRlib. */
	BGPSEC_UNSUPPORTED_ALGORITHM_SUITE = -6,
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
};

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
};

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
};

static const int algorithm_suites[] = {
	BGPSEC_ALGORITHM_SUITE_1
};

/**
 * @brief Validation function for AS path validation.
 * @param[in] data Data required for AS path validation. The asn field
 *		   refers to the own AS.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update.
 * @param[in] table The SPKI table that contains the router keys.
 * @param[in] as_hops The amount of AS hops the update has taken.
 * @return BGPSEC_VALID If the AS path was valid.
 * @return BGPSEC_NOT_VALID If the AS path was not valid.
 * @return BGPSEC_ERROR If an error occurred. Refer to error codes for
 *			more details.
 */
int rtr_bgpsec_validate_as_path(const struct bgpsec_data *data,
				const struct signature_seg *sig_segs,
				const struct secure_path_seg *sec_paths,
				const struct spki_table *table,
				const unsigned int as_hops);

/**
 * @brief Signing function for a BGPsec_PATH.
 * @param[in] data Data required for AS path validation. The asn field
 *		   refers to the target AS.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update.
 *			Must includes a segment filled with the own
 *			AS credentials.
 * @param[in] table The SPKI table that contains the router keys.
 * @param[in] as_hops The amount of AS hops the update has taken.
 * @param[out] new_signature contains the generated signature if successful.
 * @return sig_len If the signature was successfully generated.
 * @return BGPSEC_ERROR If an error occurred. Refer to error codes for
 *			more details.
 */
int rtr_bgpsec_generate_signature(const struct bgpsec_data *data,
				  const struct signature_seg *sig_segs,
				  const struct secure_path_seg *sec_paths,
				  const struct spki_table *table,
				  const unsigned int as_hops,
				  const struct secure_path_seg *own_sec_path,
				  const unsigned int target_as,
				  char *private_key,
				  char *new_signature);

/**
 * @brief Returns the highest supported BGPsec version.
 * @return BGPSEC_VERSION The currently supported BGPsec version.
 */
int rtr_bgpsec_get_version(void);

/**
 * @brief Check, if an algorithm suite is supported by RTRlib.
 * @param[in] alg_suite The algorithm suite that is to be checked.
 * @return BGPSEC_SUCCESS If the algorithm suite is supported.
 * @return BGPSEC_ERROR If the algorithm suite is not supported.
 */
int rtr_bgpsec_check_algorithm_suite(int alg_suite);

/**
 * @brief Return a char pointer to all supported algorithm suites.
 * @param[out] algs_arr A char pointer that contains all supported suites.
 * @return ALGORITHM_SUITES_COUNT The size of algs_arr
 */
int rtr_bgpsec_get_algorithm_suites_arr(int **algs_arr);

#endif
/* @} */
