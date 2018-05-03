#include <stdio.h>
#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

void createSignature()
{
    EC_KEY* eckey = EC_KEY_new();
    EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_group(eckey,ecgroup);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

    /* the private key value */
    const char *p_str = "7D22AB6A1FD3FC1F5EBEDCA222151375683B733E9DDC9CA5B2485E202C55D25C";
    BIGNUM* prv = BN_new();
    BN_hex2bn(&prv, p_str);
    EC_POINT* pub = EC_POINT_new(ecgroup);

    /* calculate the public key */
    EC_POINT_mul(ecgroup, pub, prv, NULL, NULL, NULL);

    /* add the private & public key to the EC_KEY structure */
    EC_KEY_set_private_key(eckey, prv);
    EC_KEY_set_public_key(eckey, pub);
    /* output public key in hex format */
    char* hexPKey = EC_POINT_point2hex( ecgroup, pub, POINT_CONVERSION_UNCOMPRESSED, NULL );
    printf("Public key: %s \n", hexPKey); 
    /* create hash */
    printf("Data: ");
    uint8_t data[32];
    for(int i=0; i < 32; i++) {
        data[i] = i;
        printf("%02x",data[i]);
    }
    printf("\n");

    uint8_t hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, sizeof(data));
    SHA256_Final(hash, &sha256);

    printf("Hash: ");
    for(int i=0; i < 32; i++) {
        printf("%02x",hash[i]);
    }
    printf("\n");

    /* create and verify signature */
    ECDSA_SIG* signature = ECDSA_do_sign(hash, 32, eckey);
    /* hash[0] = 0xff; // Uncomment to test if verification fails with a wrong hash */
    if (1 != ECDSA_do_verify(hash, 32, signature, eckey)) {
        printf("Failed to verify EC Signature\n");
    } else {
        printf("Verified EC Signature\n");
    }
    /*print R & S value in hex format */
    char* hexR = BN_bn2hex(signature->r);
    char* hexS = BN_bn2hex(signature->s);
    printf("R: %s \nS: %s\n", hexR, hexS);
    /* export raw signature to DER-encoded format */
    int sigSize = i2d_ECDSA_SIG(signature, NULL);
    uint8_t* derSig = (uint8_t*)malloc(sigSize);
    uint8_t* p = derSig;    //memset(sig_bytes, 6, sig_size);
    sigSize= i2d_ECDSA_SIG(signature, &p);

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, eckey);

    /* write files */
    /*FILE* fp = fopen("pubkey.pem", "w");*/
    /*PEM_write_PUBKEY(fp, pkey);*/
    /*fclose(fp);*/
    /*fp = fopen("privkey.pem", "w");*/
    /*PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, NULL);*/
    /*fclose(fp);*/
    /*fp = fopen("data.bin", "w");*/
    /*fwrite(data, 1, sizeof(data), fp);*/
    /*fclose(fp);*/
    /*fp = fopen("data_sig.der", "w");*/
    /*fwrite(derSig, 1, sigSize, fp);*/
    /*fclose(fp);*/

    /* free runtime allocated res */
    free(derSig);
    OPENSSL_free(hexPKey);
    OPENSSL_free(hexR);
    OPENSSL_free(hexS);
    BN_free(prv);
    EC_POINT_free(pub);
    EC_GROUP_free(ecgroup); 
    EC_KEY_free(eckey);
}

int main(int argc, char** argv) {
    createSignature();
    return (EXIT_SUCCESS);
}
