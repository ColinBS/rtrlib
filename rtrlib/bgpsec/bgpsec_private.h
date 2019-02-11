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

#ifndef RTR_BGPSEC_PRIVATE_H
#define RTR_BGPSEC_PRIVATE_H

#include "rtrlib/bgpsec/bgpsec.h"

/**
 * @brief Validation function for AS path validation.
 * @param[in] data Data required for AS path validation. The asn field
 *		   refers to the own AS.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update.
 * @param[in] table The SPKI table that contains the router keys.
 * @param[in] as_hops The amount of AS hops the update has taken.
 * @return RTR_BGPSEC_VALID If the AS path was valid.
 * @return RTR_BGPSEC_NOT_VALID If the AS path was not valid.
 * @return RTR_BGPSEC_ERROR If an error occurred. Refer to error codes for
 *			more details.
 */
int rtr_bgpsec_validate_as_path(const struct rtr_bgpsec_data *data,
				const struct rtr_signature_seg *sig_segs,
				const struct rtr_secure_path_seg *sec_paths,
				struct spki_table *table,
				const unsigned int as_hops);

/**
 * @brief Signing function for a BGPsec_PATH.
 * @param[in] data Data required for AS path validation. The asn field
 *		   refers to the own AS.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update, not
 *			including the own segment.
 * @param[in] as_hops The amount of AS hops the update has taken.
 * @param[in] own_sec_path The Secure_Path Segment containing the information
 *			   of the own AS.
 * @param[in] target_as The ASN of the target AS.
 * @param[in] private_key The raw private key that is used for signing.
 * @param[out] new_signature contains the generated signature if successful.
 *			     Must be at least 72 bytes of allocated memory.
 * @return sig_len If the signature was successfully generated.
 * @return RTR_BGPSEC_ERROR If an error occurred. Refer to error codes for
 *			more details.
 */
int rtr_bgpsec_generate_signature(
			const struct rtr_bgpsec_data *data,
			const struct rtr_signature_seg *sig_segs,
			const struct rtr_secure_path_seg *sec_paths,
			const unsigned int as_hops,
			const struct rtr_secure_path_seg *own_sec_path,
			const unsigned int target_as,
			uint8_t *private_key,
			uint8_t *new_signature);

/**
 * @brief Returns the highest supported BGPsec version.
 * @return RTR_BGPSEC_VERSION The currently supported BGPsec version.
 */
int rtr_bgpsec_get_version(void);

/**
 * @brief Check, if an algorithm suite is supported by RTRlib.
 * @param[in] alg_suite The algorithm suite that is to be checked.
 * @return RTR_BGPSEC_SUCCESS If the algorithm suite is supported.
 * @return RTR_BGPSEC_ERROR If the algorithm suite is not supported.
 */
int rtr_bgpsec_has_algorithm_suite(uint8_t alg_suite);

/**
 * @brief Returns pointer to a list that holds all supported algorithm suites.
 * @param[out] algs_arr A char pointer that contains all supported suites.
 * @return ALGORITHM_SUITES_COUNT The size of algs_arr
 */
int rtr_bgpsec_get_algorithm_suites(const uint8_t **algs_arr);

#endif
/* @} */
