/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "rtrlib/bgpsec/bgpsec.h"
#include "rtrlib/spki/hashtable/ht-spkitable.h"

void _print_byte_sequence(const unsigned char *bytes,
			  unsigned int bytes_size,
			  char alignment,
			  int tabstops);

void _print_bgpsec_segment(struct signature_seg *sig_seg,
			   struct secure_path_seg *sec_path);

int _calculate_val_digest(struct bgpsec_data *data,
			  struct signature_seg *sig_segs,
			  struct secure_path_seg *sec_paths,
			  const unsigned int as_hops,
			  uint8_t **bytes);

int _calculate_gen_digest(struct bgpsec_data *data,
			  struct signature_seg *sig_segs,
			  struct secure_path_seg *sec_paths,
			  const unsigned int as_hops,
			  uint8_t **bytes);

int _hash_byte_sequence(const unsigned char *bytes,
			unsigned int bytes_len,
			const unsigned char *result_buffer);

int _validate_signature(const unsigned char *hash,
			uint8_t *signature,
			uint16_t sig_len,
			uint8_t *spki,
			uint8_t *ski);

int _get_sig_segs_size(struct signature_seg *sig_segs,
		       const unsigned int sig_segs_len,
		       const unsigned int offset);

EC_KEY *_load_public_key(EC_KEY *ec_key, char *file_name);

EC_KEY *_load_private_key(EC_KEY *priv_key, char *file_name);

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

int bgpsec_validate_as_path(struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    struct spki_table *table,
			    const unsigned int as_hops)
{
	// The AS path validation result.
	int val_result;

	// bytes holds the byte sequence that is hashed.
	uint8_t *bytes;
	int bytes_len;

	// bytes_start holds the start address of bytes.
	// This is necessary because bytes address is
	// incremented after every memcpy.
	uint8_t *bytes_start;

	// This pointer points to the resulting hash.
	unsigned char *hash_result;
	int hash_result_len;

	// A temporare spki record 
	struct spki_record *tmp_key;
	int spki_count;
	
	// router_keys holds all required router keys.
	unsigned int router_keys_len;
	struct spki_record *router_keys = lrtr_malloc(sizeof(struct spki_record)
						      * as_hops);
	spki_count = 0;

	if (router_keys == NULL)
		goto err;

	// Store all router keys.
	// TODO: what, if multiple SPKI entries were found?
	for (unsigned int i = 0; i < as_hops; i++) {	
		spki_table_search_by_ski(table, sig_segs[i].ski,
					 &tmp_key, &router_keys_len);

		// Return an error, if a router key was not found.
		if (router_keys_len == 0)
			return BGPSEC_ERROR;

		memcpy(&router_keys[i], tmp_key, sizeof(struct spki_record));
		spki_count += router_keys_len;
		lrtr_free(tmp_key);
	}

	// Before the validation process in triggered, make sure that
	// all router keys are present.
	// TODO: Make appropriate error values.

	bytes_len = _calculate_val_digest(data, sig_segs, sec_paths,
					  as_hops, &bytes);

	hash_result = lrtr_malloc(SHA256_DIGEST_LENGTH);
	if (hash_result == NULL)
		goto err;

	// Finished aligning the data.
	// Hashing begins here.

	val_result = BGPSEC_VALID;

	// TODO: dynamically calculate offset size.
	for (int bytes_offset = 0, i = 0;
	     bytes_offset <= bytes_len && val_result == BGPSEC_VALID;
	     bytes_offset += BYTE_SEQUENCE_OFFSET, i++)
	{
		hash_result_len = _hash_byte_sequence((const unsigned char *)&bytes[bytes_offset],
						      (bytes_len - bytes_offset), hash_result);

		if (hash_result_len < 0)
			goto err;

		/*_print_byte_sequence(hash_result, hash_result_len, 'v', 0);*/

		// Finished hashing.
		// Validation begins here.

		val_result = _validate_signature(hash_result,
						 sig_segs[i].signature,
						 sig_segs[i].sig_len,
						 router_keys[i].spki,
						 router_keys[i].ski);
	}
	lrtr_free(bytes);
	lrtr_free(router_keys);
	lrtr_free(hash_result);

	return val_result;

err:
	lrtr_free(bytes);
	lrtr_free(router_keys);
	lrtr_free(hash_result);

	return BGPSEC_ERROR;
}

int bgpsec_create_signature(struct bgpsec_data *data,
			    struct signature_seg *sig_segs,
			    struct secure_path_seg *sec_paths,
			    struct spki_table *table,
			    const unsigned int as_hops,
			    char *ski,
			    char *new_signature)
{
	// The return value. Holds the signature length
	// if successful.
	int retval;
	
	uint8_t *bytes;
	int bytes_len;

	// bytes_start holds the start address of bytes.
	// This is necessary because bytes address is
	// incremented after every memcpy.
	uint8_t *bytes_start;

	// This pointer points to the resulting hash.
	unsigned char *hash_result;
	int hash_result_len;

	// A temporare spki record 
	struct spki_record *tmp_key;
	int spki_count;
	
	// router_keys holds all required router keys.
	struct spki_record *router_keys;
	unsigned int router_keys_len;

	spki_count = 0;

	EC_KEY *priv_key = NULL;
	int priv_key_len = 0;

	if (as_hops > 0) {
		router_keys = lrtr_malloc(sizeof(struct spki_record) * as_hops);
		if (router_keys == NULL) {
			retval = BGPSEC_ERROR;
			goto err;
		}

		// Store all router keys.
		// TODO: what, if multiple SPKI entries were found?
		for (unsigned int i = 0; i < as_hops; i++) {	
			spki_table_search_by_ski(table, sig_segs[i].ski,
						 &tmp_key, &router_keys_len);

			// Return an error, if a router key was not found.
			if (router_keys_len == 0) {
				retval = BGPSEC_ROUTER_KEY_NOT_FOUND;
				goto err;
			}

			memcpy(&router_keys[i], tmp_key, sizeof(struct spki_record));
			spki_count += router_keys_len;
			lrtr_free(tmp_key);
		}
	}

	// TODO: currently hardcoded for testing. make dynamic.
	char file_name[200] = "/home/colin/git/bgpsec-rtrlib/raw-keys/hash-keys/";
	strcat(&file_name, (char *)ski);
	strcat(&file_name, ".der");

	priv_key = _load_private_key(priv_key, file_name);

	if (priv_key == NULL) {
		retval = BGPSEC_LOAD_PRIV_KEY_ERROR;
		goto err;
	}

	// Before the validation process in triggered, make sure that
	// all router keys are present.
	// TODO: Make appropriate error values.

	bytes_len = _calculate_gen_digest(data, sig_segs, sec_paths,
					  as_hops, &bytes);

	/*_print_byte_sequence(bytes, bytes_len, 'v', 0);*/

	hash_result = lrtr_malloc(SHA256_DIGEST_LENGTH);
	if (hash_result == NULL) {
		retval = BGPSEC_ERROR;
		goto err;
	}
	
	// TODO: dynamically calculate offset size.
	hash_result_len = _hash_byte_sequence((const unsigned char *)bytes,
					      bytes_len, hash_result);

	if (hash_result_len < 0) {
		retval = BGPSEC_ERROR;
		goto err;
	}

	/*_print_byte_sequence(hash_result, hash_result_len, 'v', 0);*/

	ECDSA_sign(0, hash_result, hash_result_len, new_signature,
		   &retval, priv_key);

	if (retval < 1) {
		retval = BGPSEC_SIGN_ERROR;
	}

err:
	lrtr_free(bytes);
	if (as_hops > 0)
		lrtr_free(router_keys);
	lrtr_free(hash_result);
	EC_KEY_free(priv_key);
	priv_key = NULL;

	return retval;
}


/*************************************************
 *********** Private helper functions ************
 ************************************************/

int _calculate_val_digest(struct bgpsec_data *data,
			  struct signature_seg *sig_segs,
			  struct secure_path_seg *sec_paths,
			  const unsigned int as_hops,
			  uint8_t **bytes)
{
	int bytes_size;
	int sig_segs_size;

	uint8_t *bytes_start = NULL;

	// The size of all but the last appended Signature Segments
	// (which is the first element of the array).
	sig_segs_size = _get_sig_segs_size(sig_segs, as_hops, 1);

	// Calculate the total necessary size of bytes.
	// bgpsec_data struct in bytes is 4 + 1 + 2 + 1 + nlri_len
	bytes_size = 8 + data->nlri_len +
			 sig_segs_size +
			 (SECURE_PATH_SEGMENT_SIZE * as_hops);

	*bytes = lrtr_malloc(bytes_size);

	if (*bytes == NULL)
		return BGPSEC_ERROR;

	memset(*bytes, 0, bytes_size);

	bytes_start = *bytes;

	// Begin here to assemble the data for the digestion.

	data->asn = ntohl(data->asn);
	memcpy(*bytes, &(data->asn), ASN_SIZE);
	*bytes += ASN_SIZE;

	for (unsigned int i = 0, j = 1; i < as_hops; i++, j++) {
		// Skip the first Signature Segment and go right to segment 1
		if (j < as_hops) {
			memcpy(*bytes, sig_segs[j].ski, SKI_SIZE);
			*bytes += SKI_SIZE;

			sig_segs[j].sig_len = ntohs(sig_segs[j].sig_len);
			memcpy(*bytes, &(sig_segs[j].sig_len), SIG_LEN_SIZE);
			*bytes += SIG_LEN_SIZE;
			sig_segs[j].sig_len = htons(sig_segs[j].sig_len);

			memcpy(*bytes, sig_segs[j].signature,
			       sig_segs[j].sig_len);
			*bytes += sig_segs[j].sig_len;
		}

		// Secure Path Segment i
		sec_paths[i].asn = ntohl(sec_paths[i].asn);
		memcpy(*bytes, &sec_paths[i], sizeof(struct secure_path_seg));
		*bytes += sizeof(struct secure_path_seg);
		/*_print_bgpsec_segment(&sig_segs[i], &sec_paths[i]);*/
	}

	// The rest of the BGPsec data.
	// The size of alg_suite_id + afi + safi.
	data->afi = ntohs(data->afi);
	memcpy(*bytes, data, 4);
	*bytes += 4;
	// TODO: make trailing bits 0.
	memcpy(*bytes, data->nlri, data->nlri_len);

	// Set the pointer of bytes to the beginning.
	*bytes = bytes_start;

	/*_print_byte_sequence(*bytes, bytes_size, 'v', 0);*/

	return bytes_size;
}

int _calculate_gen_digest(struct bgpsec_data *data,
			  struct signature_seg *sig_segs,
			  struct secure_path_seg *sec_paths,
			  const unsigned int as_hops,
			  uint8_t **bytes)
{
	int bytes_size;
	int sig_segs_size;
	int sec_paths_len = as_hops + 1;

	uint8_t *bytes_start = NULL;

	// The size of all but the last appended Signature Segments
	// (which is the first element of the array).
	sig_segs_size = _get_sig_segs_size(sig_segs, as_hops, 0);

	// Calculate the total necessary size of bytes.
	// bgpsec_data struct in bytes is 4 + 1 + 2 + 1 + nlri_len
	bytes_size = 8 + data->nlri_len +
			 sig_segs_size +
			 (SECURE_PATH_SEGMENT_SIZE * sec_paths_len);

	*bytes = lrtr_malloc(bytes_size);

	if (*bytes == NULL)
		return BGPSEC_ERROR;

	memset(*bytes, 0, bytes_size);

	bytes_start = *bytes;

	// Begin here to assemble the data for the digestion.

	data->asn = ntohl(data->asn);
	memcpy(*bytes, &(data->asn), ASN_SIZE);
	*bytes += ASN_SIZE;

	for (unsigned int i = 0; i < sec_paths_len; i++) {
		if (i < as_hops) {
			memcpy(*bytes, sig_segs[i].ski, SKI_SIZE);
			*bytes += SKI_SIZE;

			sig_segs[i].sig_len = ntohs(sig_segs[i].sig_len);
			memcpy(*bytes, &(sig_segs[i].sig_len), SIG_LEN_SIZE);
			*bytes += SIG_LEN_SIZE;
			sig_segs[i].sig_len = htons(sig_segs[i].sig_len);

			memcpy(*bytes, sig_segs[i].signature,
			       sig_segs[i].sig_len);
			*bytes += sig_segs[i].sig_len;
		}

		// Secure Path Segment i
		sec_paths[i].asn = ntohl(sec_paths[i].asn);
		memcpy(*bytes, &sec_paths[i], sizeof(struct secure_path_seg));
		*bytes += sizeof(struct secure_path_seg);
		/*_print_bgpsec_segment(&sig_segs[i], &sec_paths[i]);*/
	}

	// The rest of the BGPsec data.
	// The size of alg_suite_id + afi + safi.
	data->afi = ntohs(data->afi);
	memcpy(*bytes, data, 4);
	*bytes += 4;
	// TODO: make trailing bits 0.
	memcpy(*bytes, data->nlri, data->nlri_len);

	// Set the pointer of bytes to the beginning.
	*bytes = bytes_start;

	/*_print_byte_sequence(*bytes, bytes_size, 'v', 0);*/

	return bytes_size;
}

int _validate_signature(const unsigned char *hash,
			uint8_t *signature,
			uint16_t sig_len,
			uint8_t *spki,
			uint8_t *ski)
{
	int status;
	int rtval = BGPSEC_ERROR;

	EC_KEY *pub_key = NULL;

	// Buile the file name string;
	// 20 * 2 for the ski, 5 for the file descripor, 1 for \0
	char ski_str[46];
	for (int i = 0; i < 20; i++)
		sprintf(&ski_str[i*2], "%02X", (unsigned char)ski[i]);
	strcat(&ski_str[40], ".cert");
	ski_str[45] = '\0';

	// TODO: currently hardcoded for testing. make dynamic.
	char file_name[200] = "/home/colin/git/bgpsec-rtrlib/raw-keys/hash-keys/";
	strcat(&file_name, &ski_str);

	pub_key = _load_public_key(pub_key, file_name);
	if (pub_key == NULL) {
		RTR_DBG1("ERROR: Could not read .cert file");
		rtval = BGPSEC_LOAD_PUB_KEY_ERROR;
		goto err;
	}

	status = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, pub_key);

	switch(status) {
	case -1:
		RTR_DBG1("ERROR: Failed to verify EC Signature");
		rtval = BGPSEC_ERROR;
		break;
	case 0:
		rtval = BGPSEC_NOT_VALID;
		RTR_DBG1("Validation result of signature: invalid");
		break;
	case 1:
		rtval = BGPSEC_VALID;
		RTR_DBG1("Validation result of signature: valid");
		break;
	}

err:
	EC_KEY_free(pub_key);

	return rtval;
}

// TODO: why not read the pub key like the priv key?
EC_KEY *_load_public_key(EC_KEY *pub_key, char *file_name)
{
	int status;

	X509 *certificate = NULL;
	BIO *bio = NULL;

	EC_GROUP *ec_group = NULL;
	EC_POINT *ec_point = NULL;

	int asn1_len;
	// TODO: change value to some #define
	char asn1_buffer[200];

	// Start reading the .cert file
	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return NULL;

	status = BIO_read_filename(bio, file_name);
	if (status == 0)
		goto err;

	certificate = X509_new();
	if (certificate == NULL)
		goto err;

	certificate = d2i_X509_bio(bio, &certificate);
	if (certificate == NULL)
		goto err;
	// End reading the .cert file

	// Start generating the EC Key
	ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (ec_group == NULL)
		goto err;

	ec_point = EC_POINT_new(ec_group);
	if (ec_point == NULL)
		goto err;

	memset(&asn1_buffer, '\0', 200);
	asn1_len = ASN1_STRING_length(certificate->cert_info->key->public_key);
	memcpy(asn1_buffer,
	       ASN1_STRING_data(certificate->cert_info->key->public_key),
	       asn1_len);

	pub_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (pub_key == NULL) {
		RTR_DBG1("ERROR: EC key could not be created");
		goto err;
	}

	status = EC_POINT_oct2point(ec_group, ec_point,
				    (const unsigned char *)asn1_buffer,
				    asn1_len, NULL);
	if (status == 0)
		goto err;

	status = EC_KEY_set_public_key(pub_key, ec_point);
	if (status == 0)
		goto err;

	status = EC_KEY_check_key(pub_key);
	if (status == 0) {
		RTR_DBG1("ERROR: EC key could not be generated");
		goto err;
	}
	// End generating the EC Key

	EC_GROUP_free(ec_group);
	EC_POINT_free(ec_point);
	X509_free(certificate);
	BIO_free(bio);

	return pub_key;
err:
	EC_GROUP_free(ec_group);
	EC_POINT_free(ec_point);
	X509_free(certificate);
	BIO_free(bio);
	EC_KEY_free(pub_key);

	return NULL;
}

EC_KEY *_load_private_key(EC_KEY *priv_key, char *file_name)
{
	char buffer[500];
	FILE *priv_key_file = fopen(file_name, "r");
	int priv_key_len = 0;
	int status = 0;
	char *p = buffer;

	if (priv_key_file == NULL)
		goto err;
	
	priv_key_len = fread(&buffer, sizeof(char), 500, priv_key_file);

	fclose(priv_key_file);

	priv_key = d2i_ECPrivateKey(NULL, (const unsigned char **)&p,
				    priv_key_len);

	status = EC_KEY_check_key(priv_key);
	if (status == 0)
		goto err;

	memset(buffer, 0, priv_key_len);
	memset(p, 0, priv_key_len);
	return priv_key;
err:
	// Cleanup memory
	// TODO: is this sufficient to clean priv key memory areas?
	EC_KEY_free(priv_key);
	priv_key = NULL;
	memset(buffer, 0, priv_key_len);
	memset(p, 0, priv_key_len);
	return NULL;
}

int _get_sig_segs_size(struct signature_seg *sig_segs,
		       const unsigned int sig_segs_len,
		       const unsigned int offset)
{
	int sig_segs_size = 0;
	for (int i = offset; i < sig_segs_len; i++) {
		sig_segs_size += sig_segs[i].sig_len +
				 sizeof(sig_segs[i].sig_len) +
				 SKI_SIZE;
	}
	return sig_segs_size;
}

/*************************************************
 **** Functions for versions and algo suites *****
 ************************************************/

int bgpsec_get_version()
{
	return BGPSEC_VERSION;
}

int bgpsec_check_algorithm_suite(int alg_suite)
{
	if (alg_suite == BGPSEC_ALGORITHM_SUITE_1)
		return 0;
	else
		return 1;
}

/*int bgpsec_get_algorithm_suites_arr(char *algs_arr)*/
/*{*/
	/*static char arr[ALGORITHM_SUITES_COUNT] = {BGPSEC_ALGORITHM_SUITE_1};*/
	/*algs_arr = &arr;*/
	/*return ALGORITHM_SUITES_COUNT;*/
/*}*/

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

	return SHA256_DIGEST_LENGTH;
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
