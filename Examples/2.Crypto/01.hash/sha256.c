#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>


#define BUFF_SIZE   16



int algo_main(int mode, FILE *infp, FILE *outfp,
               unsigned char *key, int key_sz,
               unsigned char *iv, int iv_sz,
               unsigned char *tag, int tag_sz)
{
    EVP_MD_CTX mdCtx;
    char in[BUFF_SIZE];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int inl;
    unsigned int dmSz;

    (void)key_sz;
    (void)iv_sz;
    (void)tag_sz;

    if (infp == NULL || key != NULL || iv != NULL || tag != NULL) {
        fprintf(stderr, "illegal parameter.\n");
        goto cleanup;
    }

    if (outfp == NULL)
        outfp = stdout;

    EVP_MD_CTX_init(&mdCtx);

    if (EVP_DigestInit(&mdCtx, EVP_sha256()) != SSL_SUCCESS) {
        fprintf(stderr, "EVP_DigestInit( failed.\n");
        goto cleanup;
    }

    while (1) {
        if ((inl = fread(in, 1, BUFF_SIZE, infp)) <0) {
            fprintf(stderr, "fread failed.\n");
            goto cleanup;
        }
        if (EVP_DigestUpdate(&mdCtx, in, inl) != SSL_SUCCESS) {
            fprintf(stderr, "EVP_DigestUpdate failed.\n");
            goto cleanup;
        }
        if(inl < BUFF_SIZE)
            break;      
    }
 
    if (EVP_DigestFinal(&mdCtx, digest, &dmSz) != SSL_SUCCESS) {
        fprintf(stderr, "EVP_DigestFinal failed.\n");
        goto cleanup;
    }

    if (fwrite(digest, dmSz, 1, outfp) != 1) {
        fprintf(stderr, "fwrite failed.\n");
        goto cleanup;
    }

cleanup:
    return 0;
}