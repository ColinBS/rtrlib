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
#include <openssl/sha.h>
#include "rtrlib/spki/spkitable.h"

#define NLRI_MAX_SIZE		4096

enum bgpsec_rtvals {
	RTR_BGPSEC_SUCCESS = 0,
	RTR_BGPSEC_ERROR = -1
};

/**
 * @brief Validation result of an AS path validation.
 */
enum bgpsec_result {
	/** All signatures are valid. */
	BGPSEC_VALID,
	/** At least one signature is not valid. */
	BGPSEC_NOT_VALID,
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
	uint8_t ski[SKI_SIZE];
	uint16_t sig_len;
	uint8_t *signature;
};

/**
 * @brief The data that is passed to the bgpsec_validate_as_path function.
 * @param target_as The AS, where the update was sent to (usually the own AS).
 * @param alg_suite_id The identifier, which algorithm suite must be used.
 * @param afi The Address Family Identifier.
 * @param safi The Subsequent Address Family Identifier.
 * @param nlri The Network Layer Reachability Information.
 * @param nlri_len The length of nlri in bytes.
 */
struct bgpsec_data {
	uint16_t target_as;
	uint8_t alg_suite_id;
	uint16_t afi;
	uint8_t safi;
	uint8_t *nlri;
	uint16_t nlri_len;
};

/**
 * @brief Validation function for AS path validation.
 * @param[in] data Data required for AS path validation.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sig_segs_len The length of the sig_segs array.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update.
 * @param[in] sec_paths_len The length of the sec_paths array.
 * @param[in] own_asn The ASN of the AS that calls this function.
 * @param[out] result Outcome of AS path validation,
 *		    either BGPSEC_VALID or BGPSEC_NOT_VALID.
 * @return RTR_BGPSEC_SUCCESS On success.
 * @return RTR_BGPSEC_ERROR If an error occurred.
 */

int bgpsec_validate_as_path(const struct bgpsec_data *data,
			    struct signature_seg *sig_segs[],
			    const unsigned int sig_segs_len,
			    struct secure_path_seg *sec_paths[],
			    const unsigned int sec_paths_len,
			    const uint32_t own_asn,
			    enum bgpsec_result *result);
#endif
