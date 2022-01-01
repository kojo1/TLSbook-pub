#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../../common/main.h"

#define CIPHER EVP_aes_128_gcm()

#define BUFF_SIZE   256

int algo_main(int mode, FILE *infp, FILE *outfp,
                 unsigned char *key, int key_sz,
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tagIn, int tag_sz)
{
    EVP_CIPHER_CTX *evp = NULL;
    unsigned char in[BUFF_SIZE];
    unsigned char out[BUFF_SIZE*2+AES_BLOCK_SIZE];
    unsigned char tagOut[BUFF_SIZE];
    int inl, outl;
    int ret = SSL_FAILURE;
    int i;

    /* Check arguments */
    if(mode < 0) mode = ENC;
    if(mode == ENC && tagIn != NULL) {
         fprintf(stderr, "ERROR: Tag Option with Enc mode\n");
        return ret;
    } else
        tag_sz = AES_BLOCK_SIZE;

    if(mode == DEC && tagIn == NULL) {
        fprintf(stderr, "ERROR: No Tag Option with Dec mode\n");
        return ret;
    }

    if(key == NULL || iv == NULL) {
        fprintf(stderr, "ERROR: Missing Option key or iv\n");
        return ret;
    }
    if (key_sz != 128 / 8) {
        fprintf(stderr, "ERROR: Key size = %d\n", key_sz);
        goto cleanup;
    }
    if (iv_sz != 96 / 8){
        fprintf(stderr, "ERROR: IV size = %d\n", iv_sz);
        goto cleanup;
    }
    
    if((evp = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_CIIPHER_CTX_new\n");
        goto cleanup;
    }

    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        goto cleanup;
    }
    /* End argment check */

    /* Start cipher process */
    while(1) {
        if((inl = fread(in, 1, BUFF_SIZE, infp)) <0) {
            fprintf(stderr, "ERROR: fread\n");
            goto cleanup;
        } 
        if (EVP_CipherUpdate(evp, out, &outl, in, inl) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: EVP_CipherUpdate\n");
            goto cleanup;
        }
        if(fwrite(out, 1, outl, outfp) != outl)
            goto cleanup;
        if (inl < BUFF_SIZE)
            break;
    }

    if (mode == DEC)
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tagIn) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(DEC)\n");
            goto cleanup;
        }

    if(EVP_CipherFinal(evp, out, &outl) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_CipherFinal\n");
        goto cleanup;
    }

    if (mode == ENC) {
        if(EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_GET_TAG, tag_sz, tagOut) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: EVP_CIPHER_CTX_ctrl(ENC)\n");
            goto cleanup;
        }
        for (i = 0; i < tag_sz; i++)
            printf("%02x", tagOut[i]);
        putchar('\n');
    }

    if(fwrite(out, 1, outl, outfp) != outl)
        goto cleanup;
    ret = SSL_SUCCESS;
    /* End cipher process */

cleanup:
    EVP_CIPHER_CTX_free(evp);
    return ret;
}