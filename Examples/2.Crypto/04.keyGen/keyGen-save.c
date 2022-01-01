

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#define CIPHER EVP_aes_128_cbc()

#define BUFF_SIZE 256

void algo_main(int mode, FILE *fpPri, FILE *fpPub,
                 unsigned char *key, int key_sz, 
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    int RsaSize = 2048;
    RSA *rsa   = NULL;
    EC_KEY *ec = NULL;
    unsigned char *pri = NULL;
    unsigned char *pub = NULL;
    int pri_sz, pub_sz;

    /* Check arguments */
    if(key != NULL || iv != NULL || tag != NULL) {
        fprintf(stderr, "Error: usage\n");
        goto cleanup;
    }
    if(mode < 0) mode = KEY_RSA;
    /* End argment check */

    /* Start cipher process */
    switch(mode) {
    case KEY_RSA:
        rsa = RSA_generate_key(RsaSize, 3, NULL, NULL);
        if(rsa == NULL) {
            fprintf(stderr, "ERROR: RSA_generate_key\n");
            goto cleanup;            
        }
        pri_sz = i2d_RSAPrivateKey(rsa, &pri);
        pub_sz = i2d_RSAPublicKey(rsa, (const unsigned char **)&pub);
        if(pri == NULL || pub == NULL) {
            fprintf(stderr, "ERROR: i2d_RSAPrivate/PublicKey\n");
            goto cleanup;
        }
        printf("pri=%d, pub=%d\n", pri_sz, pub_sz);
        break;

    case KEY_ECC:
        if((ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
            fprintf(stderr, "ERROR: EC_KEY_new_by_curve_name\n");
            goto cleanup;            
        }
        if(EC_KEY_generate_key(ec) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: EC_KEY_generate_key\n");
            goto cleanup;
        }
        pub_sz = i2d_EC_PUBKEY(ec, &pub);
        pri_sz = i2d_ECPrivateKey(ec, &pri);
        if(pri == NULL || pub == NULL) {
            fprintf(stderr, "ERROR: i2d_RSAPrivate/PublicKey\n");
            goto cleanup;
        }
        break;

    default:
        fprintf(stderr, "ERROR: Mode option\n");
        goto cleanup;
    }

    if(fwrite(pub, 1, pub_sz, fpPub) != pub_sz) {
        fprintf(stderr, "ERROR: fwrite Pub key\n");
        goto cleanup;
    }

    if(pri != NULL) {
        if(fwrite(pri, 1, pri_sz, fpPri) != pri_sz) {
            fprintf(stderr, "ERROR: fwrite Private key\n");
            goto cleanup;
        }
    }

cleanup:
    if(rsa!= NULL)free(rsa);
    if(ec!= NULL)free(ec);
    if(pri!= NULL)free(pri);
    if(pub!= NULL)free(pub);
    if(fpPri != NULL)fclose(fpPri);
    if(fpPub != NULL)fclose(fpPub);
    return;
}