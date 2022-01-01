#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../../common/main.h"

#define CIPHER EVP_aes_128_cbc()

#define BUFF_SIZE   256

int algo_main(int mode, FILE *infp, FILE *outfp,
               unsigned char *key, int key_sz,
               unsigned char *iv, int iv_sz,
               unsigned char *tag, int tag_sz)
{
    EVP_CIPHER_CTX *evp = NULL;
    unsigned char in[BUFF_SIZE];
    unsigned char out[BUFF_SIZE+AES_BLOCK_SIZE];
    int inl, outl;
    int ret = SSL_FAILURE;         

    /* Check arguments */
    if (tag != NULL || key == NULL || iv == NULL) {
        fprintf(stderr, "ERROR: Option\n");
        return ret;
    }
    if(mode < 0)mode = ENC;
    if(key_sz != 128/8) {
        fprintf(stderr, "ERROR: Key size = %d\n", key_sz);
        goto cleanup;
    }
    if(iv_sz != 128/8) {
        fprintf(stderr, "ERROR: IV size = %d\n", iv_sz);
        goto cleanup;
    }

    /* End argment check */

    if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_CIIPHER_CTX_new\n");
        goto cleanup;
    }

    /* Start cipher process */
    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        goto cleanup;
    }

    while(1) {
        if((inl = fread(in, 1, BUFF_SIZE, infp)) <0) {
            fprintf(stderr, "ERROR: fread\n");
            goto cleanup;
        }
        if (EVP_CipherUpdate(evp, out, &outl, in, inl) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: EVP_CipherUpdate(\n");
            goto cleanup;
        }
        fwrite(out, 1, outl, outfp);
        if (inl < BUFF_SIZE)
            break;
    }

    if(EVP_CipherFinal(evp, out, &outl)  != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_CipherFinal\n");
        goto cleanup;
    }
    fwrite(out, 1, outl, outfp);
    ret = SSL_SUCCESS;
    /* End cipher process */

cleanup:
    EVP_CIPHER_CTX_free(evp);
    return ret;
}