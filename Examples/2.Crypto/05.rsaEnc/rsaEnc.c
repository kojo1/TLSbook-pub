

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

int algo_main(int mode, FILE *fpKey, FILE *fpEnc,
                 unsigned char *key, int key_sz,
                 unsigned char *iv, int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    /***
        infp: RSA key in DER for Encrypt
        stdin: Message to Encrypt
        outfp: Encrypted message
    ***/

    EVP_PKEY  *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    #define KEY_SIZE 2048
    unsigned char key_buff[KEY_SIZE];
    const unsigned char *p = key_buff;
    #define ENC_SIZE 256
    unsigned char enc[ENC_SIZE];
    #define BUFF_SIZE 512
    unsigned char msg[BUFF_SIZE];
    size_t enc_sz;
    size_t msg_sz;
    int ret = SSL_FAILURE;

    /* Check arguments */
    if (mode >= 0 || fpKey == NULL || fpEnc== NULL 
        || tag != NULL || key != NULL || iv != NULL) {
        fprintf(stderr, "ERROR: command argment\n");
        return ret;
    }

    /* End argment check */

    if ((msg_sz = fread(msg, 1, BUFF_SIZE, stdin)) < 0)
    {
        fprintf(stderr, "ERROR: fread\n");
        goto cleanup;
    }

    if((key_sz = fread(key_buff, 1, sizeof(key_buff), fpKey)) < 0) {
        fprintf(stderr, "ERROR: read key\n");
        return ret;
    }

    if((pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, key_sz)) == NULL) {
        fprintf(stderr, "ERROR: d2i_PublicKey\n");
        goto cleanup;
    }

    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        fprintf(stderr, "ERROR: EEVP_PKEY_CTX_new\n");
        goto cleanup;
    }

    if(EVP_PKEY_encrypt_init(ctx) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_PKEY_encrypt_init\n");
        goto cleanup;       
    }

    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_PKEY_CTX_set_rsa_padding\n");
        goto cleanup;  
    }

    if(EVP_PKEY_encrypt(ctx, NULL, &enc_sz, msg, msg_sz) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_PKEY_encrypt\n");
        goto cleanup;  
    }
    if (ENC_SIZE != enc_sz) {
        fprintf(stderr, "ERROR: Message size error\n");
        goto cleanup;
    }

    if(EVP_PKEY_encrypt(ctx, enc, &enc_sz, (const unsigned char *)msg, msg_sz)!= SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_PKEY_encrypt\n");
        goto cleanup;  
    }

    if(fwrite(enc, 1, enc_sz, fpEnc) != enc_sz) {
        fprintf(stderr, "ERROR: fwrite\n");
        goto cleanup;
    }

cleanup:
    if(ctx != NULL)EVP_PKEY_CTX_free(ctx);
    if(pkey != NULL)EVP_PKEY_free(pkey);

    return ret;
}
