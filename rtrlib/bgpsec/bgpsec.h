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

#ifndef RTR_BGPSEC_H
#define RTR_BGPSEC_H

#include <stdint.h>

#include "rtrlib/spki/spkitable.h"

/**
 * @brief All supported algorithm suites.
 */
enum rtr_bgpsec_algorithm_suites {
	/** Algorithm suite 1 */
	RTR_BGPSEC_ALGORITHM_SUITE_1 = 1,
};

/**
 * @brief Status codes for various cases.
 */
enum rtr_bgpsec_rtvals {
	/** At least one signature is not valid. */
	RTR_BGPSEC_NOT_VALID = 2,
	/** All signatures are valid. */
	RTR_BGPSEC_VALID = 1,
	/** An operation was successful. */
	RTR_BGPSEC_SUCCESS = 0,
	/** An operation was not sucessful. */
	RTR_BGPSEC_ERROR = -1,
	/** The public key could not be loaded. */
	RTR_BGPSEC_LOAD_PUB_KEY_ERROR = -2,
	/** The private key could not be loaded. */
	RTR_BGPSEC_LOAD_PRIV_KEY_ERROR = -3,
	/** The SKI for a router key was not found. */
	RTR_BGPSEC_ROUTER_KEY_NOT_FOUND = -4,
	/** An error during signing occurred. */
	RTR_BGPSEC_SIGNING_ERROR = -5,
	/** The specified algorithm suite is not supported by RTRlib. */
	RTR_BGPSEC_UNSUPPORTED_ALGORITHM_SUITE = -6,
};

/**
 * @brief A single Secure_Path Segment.
 * @param pcount The pCount field of the segment.
 * @param conf_seg The Confed Segment flag of the segment.
 * @param asn The ASN of the Segment.
 */
struct rtr_secure_path_seg {
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
struct rtr_signature_seg {
	uint8_t *ski;
	uint16_t sig_len;
	uint8_t *signature;
};

/**
 * @brief The data that is passed to the bgpsec_validate_as_path function.
 * @param alg_suite_id The identifier, which algorithm suite must be used.
 * @param safi The Subsequent Address Family Identifier.
 * @param afi The Address Family Identifier.
 * @param asn The AS Number of the AS that is currently performing validation.
 * @param nlri The Network Layer Reachability Information. Trailing bits must
 *	       be set to 0.
 * @param nlri_len The length of nlri in bits.
 */
struct rtr_bgpsec_data {
	uint8_t alg_suite_id;
	uint8_t safi;
	uint16_t afi;
	uint32_t asn;
	uint8_t *nlri;
	uint8_t nlri_len;
};

#endif
/* @} */
