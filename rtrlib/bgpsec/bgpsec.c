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
			    struct signature_seg *sig_segs[],
			    const unsigned int sig_segs_len,
			    struct secure_path_seg *sec_paths[],
			    const unsigned int sec_paths_len,
			    const uint32_t own_asn,
			    enum bgpsec_result *result)
{
	uint8_t bytes[BYTES_MAX_LEN]; // Which size?
	/*bytes += own_as;*/
	int as_hops;
	for (as_hops = (sec_paths_len - 1); as_hops >= 0; as_hops--) {
		if ((as_hops - 1) >= 0) {
			/*bytes += sig_segs[as_hops - 1]->ski;*/
			/*bytes += sig_segs[as_hops - 1]->sig_len;*/
			/*bytes += sig_segs[as_hops - 1]->signature;*/
		}
		/*bytes += sec_paths[as_hops]->pcount;*/
		/*bytes += sec_paths[as_hops]->conf_seg;*/
		/*bytes += sec_paths[as_hops]->asn;*/
	}
	*result = BGPSEC_VALID;
	return RTR_BGPSEC_SUCCESS;
}
