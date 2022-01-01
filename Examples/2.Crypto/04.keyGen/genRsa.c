

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#define RSA_SIZE 2048
#define RSA_E    3

int algo_main(int mode, FILE *fpPri, FILE *fpPub,
                 unsigned char *key, int key_sz, 
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    RSA *rsa   = NULL;
    unsigned char *pri = NULL;
    unsigned char *pub = NULL;
    int pri_sz, pub_sz;
    int ret = SSL_FAILURE;

    /* Check arguments */
    if(key != NULL || iv != NULL || tag != NULL) {
        fprintf(stderr, "Error: usage\n");
        goto cleanup;
    }
    /* End argment check */

    rsa = RSA_generate_key(RSA_SIZE, RSA_E, NULL, NULL);
    if(rsa == NULL) {
        fprintf(stderr, "ERROR: RSA_generate_key\n");
        goto cleanup;            
    }
    pri_sz = i2d_RSAPrivateKey(rsa, &pri);
    pub_sz = i2d_RSAPublicKey(rsa, &pub);
    if (pri == NULL || pub == NULL)
    {
        fprintf(stderr, "ERROR: i2d_RSAPrivate/PublicKey\n");
        goto cleanup;
    }
    
    if (fwrite(pub, 1, pub_sz, fpPub) != pub_sz) {
        fprintf(stderr, "ERROR: fwrite Pub key\n");
        goto cleanup;
    }

    if (fwrite(pri, 1, pri_sz, fpPri) != pri_sz) {
        fprintf(stderr, "ERROR: fwrite Private key\n");
        goto cleanup;
    }
    ret = SSL_SUCCESS;

cleanup:
    if(rsa!= NULL)free(rsa);
    if(pri!= NULL)free(pri);
    if(pub!= NULL)free(pub);
    if(fpPri != NULL)fclose(fpPri);
    if(fpPub != NULL)fclose(fpPub);
    return ret;
}