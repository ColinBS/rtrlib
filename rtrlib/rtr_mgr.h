/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

/**
 * @defgroup mod_rtr_mgr_h RTR connection manager
 * @brief The RTR connection manager maintains multiple groups of @ref
 * rtr_socket "RTR sockets".
 * @details The RTR connection manager is initialized with one or multiple
 * groups of rtr_sockets. Each group is configured with a preference
 * value and contains a set of rtr_socket RTR sockets. It connects to all
 * sockets of the group with the lowest preference value.\n
 * In case of failures, the connection manager establishes connections to
 * RTR servers of another group with the next lowest preference value (see
 * <a href="https://tools.ietf.org/html/rfc6810">IETF
 * RFC 6810</a> for details about error handling).\n
 * RTRlib also supports a Retry Interval (see
 * <a href="https://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-rfc6810-bis">
 * draft-ietf-sidr-rpki-rtr-rfc6810-bis</a>).
 * If a more preferred group is online again, the RTR connection manager
 * will switch back and close connections to the caches of the less
 * preferred group.
 *
 * @{
 * @example rtr_mgr.c
 * Usage example of the RTR connection manager.
 */
#ifndef RTR_MGR
#define RTR_MGR
#include <stdint.h>
#include <pthread.h>

#include "rtrlib/pfx/pfx.h"
#include "rtrlib/spki/spkitable.h"
#ifdef RTRLIB_BGPSEC
#include "rtrlib/bgpsec/bgpsec.h"
#endif

/**
 * @brief Status of a rtr_mgr_group.
 */
enum rtr_mgr_status {
	/** RTR sockets are disconnected */
	RTR_MGR_CLOSED,
	/** RTR sockets trying to establish a connection. */
	RTR_MGR_CONNECTING,
	/** All RTR sockets of the group are synchronized with rtr servers. */
	RTR_MGR_ESTABLISHED,
	/** Error occurred on at least one RTR socket. */
	RTR_MGR_ERROR,
};

/**
 * @brief A set of RTR sockets.
 * @param sockets Array of rtr_socket pointer. The tr_socket element of
 *		the rtr_socket must be associated with an initialized #
 *		transport socket.
 * @param sockets_len Number of elements in the sockets array.
 * @param preference The preference value of this group.
 *		   Groups with lower preference values are preferred.
 * @param status Status of the group.
 */
struct rtr_mgr_group {
	struct rtr_socket **sockets;
	unsigned int sockets_len;
	uint8_t preference;
	enum rtr_mgr_status status;
};

typedef void (*rtr_mgr_status_fp)(const struct rtr_mgr_group *,
				  enum rtr_mgr_status,
				  const struct rtr_socket *,
				  void *);

struct tommy_list_wrapper;

//TODO Add refresh, expire, and retry intervals to config for easier access.
struct rtr_mgr_config {
	struct tommy_list_wrapper *groups;
	unsigned int len;
	pthread_mutex_t mutex;
	rtr_mgr_status_fp status_fp;
	void *status_fp_data;
	struct pfx_table *pfx_table;
	struct spki_table *spki_table;
};

/**
 * @brief Initializes a rtr_mgr_config.
 * @param[out] config_out The rtr_mgr_config that will be initialized by this
 *			function. On error, *config_out will be NULL!
 * @param[in] groups Linked list of rtr_mgr_group. Every RTR socket in an
 *		     rtr_mgr_group must be assoziated with an initialized
 *		     transport socket. A Transport socket is only allowed to be
 *		     associated with one rtr socket. The preference values must
 *		     be unique in the linked list. More than one rtr_mgr_group
 *		     with the same preference value isn't allowed.
 * @param[in] groups_len Number of elements in the groups array. Must be >= 1.
 * @param[in] refresh_interval Interval in seconds between serial queries that
 *			     are sent to the server. Must be >= 1 and <=
 *			     86400s (1d), recommended default is 3600s (1h).
 * @param[in] expire_interval Stored validation records will be deleted if
 *			    cache was unable to refresh data for this period.
 *			    The value should be twice the refresh_interval
 *			    and must be >= 600s (10min) and <= 172800s (2d).
 *			    The recommended default is 7200s (2h).
 * @param[in] retry_interval This parameter tells the router how long to wait
 *			   (in seconds) before retrying a failed Serial Query
 *			   or Reset Query.
 *			   The value must be >= 1s and <= 7200s (2h).
 *			   The recommended default is 600s (10min).
 * @param[in] update_fp Pointer to pfx_update_fp callback, that is executed for
			every added and removed pfx_record.
 * @param[in] spki_update_fp Pointer to spki_update_fp callback, that is
			     executed for every added and removed spki_record.
 * @param[in] status_fp Pointer to a function that is called if the connection
 *			status from one of the socket groups is changed.
 * @param[in] status_fp_data Pointer to a memory area that is passed to the
 *			     status_fp function. Memory area can be freely used
 *			     to pass user-defined data to the status_fp
 *			     callback.
 * @return RTR_ERROR If an error occurred
 * @return RTR_INVALID_PARAM If refresh_interval or expire_interval is invalid.
 * @return RTR_SUCCESS On success.
 */
int rtr_mgr_init(struct rtr_mgr_config **config_out,
		 struct rtr_mgr_group groups[],
		 const unsigned int groups_len,
		 const unsigned int refresh_interval,
		 const unsigned int expire_interval,
		 const unsigned int retry_interval,
		 const pfx_update_fp update_fp,
		 const spki_update_fp spki_update_fp,
		 const rtr_mgr_status_fp status_fp,
		 void *status_fp_data);

/**
 * @brief Adds a new rtr_mgr_group to the linked list of a initialized config.
 * @details A new group must have at least one rtr_socket associated
 *          with it. This socket must have at least one initialized
 *          transport socket associated with it. The new group must
 *          have a preference value that is none of the already present
 *          groups have. More than one rtr_mgr_group with the same
 *          preference is not allowed.
 * @param config A rtr_mgr_config struct that has been initialized
 *           previously with rtr_mgr_init
 * @param group A rtr_mgr_group with at least one rtr_socket and a
 *           preference value that no existing group has.
 * @return RTR_INVALID_PARAM If a group with the same preference value already
 *           exists.
 * @return RTR_ERROR If an error occurred while adding the group.
 * @return RTR_SUCCESS If the group was successfully added.
 *
 */
int rtr_mgr_add_group(struct rtr_mgr_config *config,
		      const struct rtr_mgr_group *group);
/**
 * @brief Removes an existing rtr_mgr_group from the linked list of config.
 * @details The group to be removed is identified by its preference value.
 *          Should the group to be removed be currently active, it will be
 *          shut down and the next best group will be spun up.
 * @param config A rtr_mgr_config struct that has been initialized previously
 *          with rtr_mgr_init
 * @param preference The preference value of the group to be removed.
 * @return RTR_ERROR If no group with this preference value exists.
 * @return RTR_SUCCESS If group was successfully removed.
 *
 */
int rtr_mgr_remove_group(struct rtr_mgr_config *config,
			 unsigned int preference);
/**
 * @brief Frees all resources that were allocated from the rtr_mgr.
 * @details rtr_mgr_stop must be called before, to shutdown all rtr_sockets.
 * @param[in] config rtr_mgr_config.
 */
void rtr_mgr_free(struct rtr_mgr_config *config);

/**
 * @brief Establishes rtr_socket connections
 * @details Establishes the connection with the rtr_sockets of the group
 * with the lowest preference value and handles errors as defined in the
 * RPKI-RTR protocol.
 * @param[in] config Pointer to an initialized rtr_mgr_config.
 * @return RTR_SUCCESS On success
 * @return RTR_ERROR On error
 */
int rtr_mgr_start(struct rtr_mgr_config *config);

/**
 * @brief Terminates rtr_socket connections
 * @details Terminates all rtr_socket connections defined in the config.
 * All pfx_records received from these sockets will be purged.
 * @param[in] config The rtr_mgr_config struct
 */
void rtr_mgr_stop(struct rtr_mgr_config *config);

/**
 * @brief Check if rtr_mgr_group is fully synchronized with at least one group.
 * @param[in] config The rtr_mgr_config.
 * @return true If pfx_table stores non-outdated pfx_records
 * @return false If pfx_table isn't fully synchronized with at least one group.
 */
bool rtr_mgr_conf_in_sync(struct rtr_mgr_config *config);

/**
 * @brief Validates the origin of a BGP-Route.
 * @param[in] config The rtr_mgr_config
 * @param[in] asn Autonomous system number of the Origin-AS of the prefix
 * @param[in] prefix Announced network prefix
 * @param[in] mask_len Length of the network mask of the announced prefix
 * @param[out] result Outcome of the validation
 * @return PFX_SUCCESS On success.
 * @return PFX_ERROR If an error occurred.
 */
int rtr_mgr_validate(struct rtr_mgr_config *config,
		     const uint32_t asn,
		     const struct lrtr_ip_addr *prefix,
		     const uint8_t mask_len,
		     enum pfxv_state *result);

/**
 * @brief Returns all SPKI records which match the given ASN and SKI.
 * @param[in] config
 * @param[in] asn Autonomous system number of the Origin-AS
 * @param[in] ski the SKI to search for
 * @param[out] result a array of all matching spki_records
 * @param[out] result_count number of returned spki_records
 * @return SPKI_SUCCESS On success
 * @return SPKI_ERROR If an error occurred
 */
int rtr_mgr_get_spki(struct rtr_mgr_config *config,
		     const uint32_t asn,
		     uint8_t *ski,
		     struct spki_record **result,
		     unsigned int *result_count);

/**
 * @brief Converts a rtr_mgr_status to a String.
 * @param[in] status state to convert to a string.
 * @return NULL If status isn't a valid rtr_mgr_status.
 * @return !=NULL The rtr_rtr_mgr_status as String.
 */
const char *rtr_mgr_status_to_str(enum rtr_mgr_status status);

/**
 * @brief Iterates over all IPv4 records in the pfx_table.
 * @details For every pfx_record the function fp is called. The pfx_record and
 * the data pointer is passed to the fp.
 * @param[in] config rtr_mgr_config
 * @param[in] fp Pointer to callback function with signature \c pfx_for_each_fp.
 * @param[in] data This parameter is forwarded to the callback function.
 */
void rtr_mgr_for_each_ipv4_record(struct rtr_mgr_config *config,
				  pfx_for_each_fp fp,
				  void *data);

/**
 * @brief Iterates over all IPv6 records in the pfx_table.
 * @details For every pfx_record the function fp is called. The pfx_record and
 * the data pointer is passed to the fp.
 * @param[in] config rtr_mgr_config
 * @param[in] fp Pointer to callback function with signature \c pfx_for_each_fp.
 * @param[in] data This parameter is forwarded to the callback function.
 */
void rtr_mgr_for_each_ipv6_record(struct rtr_mgr_config *config,
				  pfx_for_each_fp fp,
				  void *data);

/**
 * @brief Returns the first, thus active group.
 * @param[in] config The rtr_mgr_config
 * @return rtr_mgr_group The head of the linked list.
 */
struct rtr_mgr_group *rtr_mgr_get_first_group(struct rtr_mgr_config *config);

int rtr_mgr_for_each_group(struct rtr_mgr_config *config,
			   void (*fp)(const struct rtr_mgr_group *group,
				      void *data),
			   void *data);

#ifdef RTRLIB_BGPSEC
/**
 * @brief Validation function for AS path validation.
 * @param[in] data Data required for AS path validation. The asn field
 *		   refers to the own AS.
 * @param[in] sig_segs All Signature Segments of a BGPsec update.
 * @param[in] sec_paths All Secure_Path Segments of a BGPsec update.
 * @param[in] config The rtr_mgr_config containing a SPKI table.
 * @param[in] as_hops The amount of AS hops the update has taken.
 * @return RTR_BGPSEC_VALID If the AS path was valid.
 * @return RTR_BGPSEC_NOT_VALID If the AS path was not valid.
 * @return RTR_BGPSEC_ERROR If an error occurred. Refer to error codes for
 *			more details.
 */
int rtr_mgr_bgpsec_validate_as_path(
			const struct rtr_bgpsec_data *data,
			const struct rtr_signature_seg *sig_segs,
			const struct rtr_secure_path_seg *sec_paths,
			struct rtr_mgr_config *config,
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
int rtr_mgr_bgpsec_generate_signature(
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
int rtr_mgr_bgpsec_get_version(void);

/**
 * @brief Check, if an algorithm suite is supported by RTRlib.
 * @param[in] alg_suite The algorithm suite that is to be checked.
 * @return RTR_BGPSEC_SUCCESS If the algorithm suite is supported.
 * @return RTR_BGPSEC_ERROR If the algorithm suite is not supported.
 */
int rtr_mgr_bgpsec_has_algorithm_suite(unsigned int alg_suite);

/**
 * @brief Returns pointer to a list that holds all supported algorithm suites.
 * @param[out] algs_arr A char pointer that contains all supported suites.
 * @return ALGORITHM_SUITES_COUNT The size of algs_arr
 */
int rtr_mgr_bgpsec_get_algorithm_suites(const uint8_t **algs_arr);
#endif

#endif
/* @} */
