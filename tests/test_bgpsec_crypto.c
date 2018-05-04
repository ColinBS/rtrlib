/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "rtrlib/bgpsec/bgpsec.h"

#ifdef BGPSEC

void create_key_test(void)
{
	EC_KEY *eckey;
	bgpsec_create_ec_key(&eckey);
	assert(eckey != NULL);
	EC_KEY_free(eckey);
}

void create_signature_test(void)
{
	int rtval;

	const unsigned char *val_digest_str1 = "0123456789abcdef";
	const unsigned char *val_digest_str2 = "fedcba9876543210";
	unsigned char *val_digest_hash1 = NULL;
	unsigned char *val_digest_hash2 = NULL;

	EC_KEY *eckey;
	ECDSA_SIG *signature1;
	ECDSA_SIG *signature2;

	bgpsec_create_ec_key(&eckey);
	assert(eckey != NULL);

	bgpsec_string_to_hash(val_digest_str1, &val_digest_hash1);
	bgpsec_string_to_hash(val_digest_str2, &val_digest_hash2);

	rtval = bgpsec_create_ecdsa_signature(val_digest_hash1, &eckey, &signature1);
	assert(rtval == RTR_BGPSEC_SUCCESS);

	rtval = bgpsec_create_ecdsa_signature(val_digest_hash2, &eckey, &signature2);
	assert(rtval == RTR_BGPSEC_SUCCESS);

	EC_KEY_free(eckey);
	ECDSA_SIG_free(signature1);
	ECDSA_SIG_free(signature2);
	free(val_digest_hash1);
	free(val_digest_hash2);
}

void signature_to_bytes_test(void)
{
	int rtval;
	enum bgpsec_result result;

	int sig_size;
	uint8_t *der_sig = NULL;
	uint8_t *p = NULL;

	int sig_size2;
	uint8_t *der_sig2 = NULL;
	uint8_t *p2 = NULL;

	const unsigned char *val_digest_str1 = "0123456789abcdef";
	const unsigned char *val_digest_str2 = "fedcba9876543210";
	unsigned char *val_digest_hash1 = NULL;
	unsigned char *val_digest_hash2 = NULL;

	EC_KEY *eckey;
	ECDSA_SIG *signature1;
	ECDSA_SIG *signature2;

	bgpsec_create_ec_key(&eckey);
	assert(eckey != NULL);

	bgpsec_string_to_hash(val_digest_str1, &val_digest_hash1);
	bgpsec_string_to_hash(val_digest_str2, &val_digest_hash2);

	bgpsec_create_ecdsa_signature(val_digest_hash1, &eckey, &signature1);
	bgpsec_create_ecdsa_signature(val_digest_hash2, &eckey, &signature2);

	// Get the size of the signature
	sig_size = i2d_ECDSA_SIG(signature1, NULL);
	// Allocate memory for the signature and give it to p
	der_sig = (uint8_t *)malloc(sig_size);
	p = der_sig;
	// Write the encoded (unsigned char) signature to p
	sig_size = i2d_ECDSA_SIG(signature1, &p);

	char hex[SHA256_DIGEST_LENGTH*2+1];

	for (int i = 0; i < sig_size; i++)
		sprintf(&hex[i*2], "%02x", (unsigned int)der_sig[i]);

	printf("%s\n", hex);

	ECDSA_SIG *result_sig = d2i_ECDSA_SIG(NULL, &der_sig, sig_size);

	// Get the size of the signature
	sig_size2 = i2d_ECDSA_SIG(result_sig, NULL);
	// Allocate memory for the signature and give it to p
	der_sig2 = (uint8_t *)malloc(sig_size2);
	p2 = der_sig2;
	// Write the encoded (unsigned char) signature to p
	sig_size2 = i2d_ECDSA_SIG(result_sig, &p2);

	char hex2[SHA256_DIGEST_LENGTH*2+1];

	for (int i = 0; i < sig_size; i++)
		sprintf(&hex2[i*2], "%02x", (unsigned int)der_sig2[i]);

	printf("%s\n", hex2);

	/*rtval = bgpsec_validate_ecdsa_signature(val_digest_hash1, &eckey, &signature1, &result);*/
	/*assert(rtval == RTR_BGPSEC_SUCCESS);*/
	/*assert(result == BGPSEC_VALID);*/

	/*rtval = bgpsec_validate_ecdsa_signature(val_digest_hash1, &eckey, &result_sig, &result);*/
	/*assert(rtval == RTR_BGPSEC_SUCCESS);*/
	/*assert(result == BGPSEC_VALID);*/

	/*_print_signature_as_string(&signature1);*/
	/*_print_signature_as_string(&result_sig);*/

	EC_KEY_free(eckey);
	ECDSA_SIG_free(signature1);
	ECDSA_SIG_free(signature2);
	free(val_digest_hash1);
	free(val_digest_hash2);
	free(der_sig);

	/*FILE *fp = fopen("daga_sig.der", "w");*/
	/*fwrite(der_sig, 1, sig_size, fp);*/

	/*unsigned char *str[1024] = {0};*/
	/*const char *val_digest1 = "0123456789abcdef";*/

	/*EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);*/
	/*if (eckey == NULL) {*/
		/*RTR_DBG1("ERROR: EC key could not be created");*/
		/*return RTR_BGPSEC_ERROR;*/
	/*}*/

	/*if (EC_KEY_generate_key(eckey) != 1) {*/
		/*RTR_DBG1("ERROR: EC key could not be generated");*/
		/*EC_KEY_free(eckey);*/
		/*return RTR_BGPSEC_ERROR;*/
	/*}*/

	/*ECDSA_SIG *sig = ECDSA_do_sign((const unsigned char *)str, strlen(str), eckey);*/
	/*if (sig == NULL) {*/
		/*RTR_DBG1("ERROR: EC Signature could not be generated");*/
		/*return RTR_BGPSEC_ERROR;*/
	/*}*/
}

void signature_transform_test(void)
{
	int rtval;
	enum bgpsec_result result;

	int sig_size, sig_size2;

	const unsigned char *val_digest_str = "0123456789abcdef";
	unsigned char *val_digest_hash = NULL;

	EC_KEY *eckey;
	ECDSA_SIG *signature;

	bgpsec_create_ec_key(&eckey);
	bgpsec_string_to_hash(val_digest_str, &val_digest_hash);
	bgpsec_create_ecdsa_signature(val_digest_hash, &eckey, &signature);

	// Transform the signature into bytes
	// Get the size of the signature
	sig_size = i2d_ECDSA_SIG(signature, NULL);
	// Allocate memory for the signature and give it to p
	uint8_t *der_sig = (uint8_t *)malloc(sig_size);
	uint8_t *p = der_sig;
	// Write the encoded (unsigned char) signature to p
	sig_size = i2d_ECDSA_SIG(signature, &p);

	// Transform the bytes back into a signature
	ECDSA_SIG *result_sig = d2i_ECDSA_SIG(NULL, &p, sig_size);

	rtval = bgpsec_validate_ecdsa_signature(val_digest_hash, &eckey, &signature, &result);
	assert(rtval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);

	// TODO: This signature fails the validation and I don't know why.
	rtval = bgpsec_validate_ecdsa_signature(val_digest_hash, &eckey, &result_sig, &result);
	assert(rtval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);
}

void validate_signature_test(void)
{
	int rtval;
	enum bgpsec_result result;

	const char *val_digest1 = "0123456789abcdef";
	const char *val_digest2 = "fedcba9876543210";
	const char *inval_digest1 = "0a1b2c3d4e5f6789";
	const char *inval_digest2 = "a0b1c2d3e4f56789";

	EC_KEY *eckey;
	ECDSA_SIG *signature1;
	ECDSA_SIG *signature2;

	bgpsec_create_ec_key(&eckey);
	assert(eckey != NULL);

	// create the signatures.
	rtval = bgpsec_create_ecdsa_signature(val_digest1, &eckey, &signature1);
	assert(rtval == RTR_BGPSEC_SUCCESS);

	rtval = bgpsec_create_ecdsa_signature(val_digest2, &eckey, &signature2);
	assert(rtval == RTR_BGPSEC_SUCCESS);

	// validate the signatures.
	rtval = bgpsec_validate_ecdsa_signature(val_digest1, &eckey, &signature1, &result);
	assert(rtval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);

	rtval = bgpsec_validate_ecdsa_signature(val_digest2, &eckey, &signature2, &result);
	assert(rtval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_VALID);

	// validate the signatures with a wrong message.
	rtval = bgpsec_validate_ecdsa_signature(inval_digest1, &eckey, &signature1, &result);
	assert(rtval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_NOT_VALID);

	rtval = bgpsec_validate_ecdsa_signature(inval_digest2, &eckey, &signature2, &result);
	assert(rtval == RTR_BGPSEC_SUCCESS);
	assert(result == BGPSEC_NOT_VALID);

	EC_KEY_free(eckey);
	ECDSA_SIG_free(signature1);
	ECDSA_SIG_free(signature2);
}

static void ssl_test(void)
{
	int result;

	const unsigned char *input = "Test String";
	char exp[] = "30c6ff7a44f7035af933babaea771bf177fc38f06482ad06434cbcc04de7ac14";

	unsigned char *output = NULL;
	unsigned char *hex = NULL;

	result = bgpsec_string_to_hash(input, &output);
	assert(result == RTR_BGPSEC_SUCCESS);

	result = bgpsec_hash_to_string(output, &hex);
	assert(result == RTR_BGPSEC_SUCCESS);

	assert(strcmp(hex, exp) == 0);

	free(output);
	free(hex);
}

#endif

int main(void)
{
#ifdef BGPSEC
	/*ssl_test();*/
	/*create_key_test();*/
	/*create_signature_test();*/
	/*validate_signature_test();*/
	/*signature_to_bytes_test();*/
	signature_transform_test();
	printf("Test successful\n");
#endif
	return EXIT_SUCCESS;
}
