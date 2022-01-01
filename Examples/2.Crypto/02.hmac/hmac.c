#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#define BUFF_SIZE   16

int algo_main(int mode, FILE *infp, FILE *outfp,
               unsigned char *key, int key_sz,
               unsigned char *iv, int iv_sz,
               unsigned char *tag, int tag_sz)
{
    HMAC_CTX* hctx = NULL;
    char in[BUFF_SIZE];
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int len;
    int inl;
    const EVP_MD *md = NULL;

    (void)iv_sz;
    (void)tag_sz;

    if (infp == NULL || key == NULL || key_sz == 0 || iv != NULL || tag != NULL) {
        fprintf(stderr, "illegal parameter.\n");
        goto cleanup;
    }

    if (outfp == NULL)
        outfp = stdout;
    printf("key: %02x %02x size = %d\n", key[0], key[1], key_sz);
    md = EVP_get_digestbyname("SHA1");
    if (md == NULL) {
        fprintf(stderr, "EVP_get_digestbyname failed.\n");
        goto cleanup;
    }

    if ((hctx = HMAC_CTX_new()) == NULL) {
        fprintf(stderr, "HMAC_CTX_new failed.\n");
        goto cleanup;        
    }

    if (HMAC_Init_ex(hctx, key, key_sz, md, NULL) != SSL_SUCCESS) {
        fprintf(stderr, "HMAC_Init failed.\n");
        goto cleanup;
    }

    while (1) {
        if ((inl = fread(in, 1, BUFF_SIZE, infp)) <0) {
            fprintf(stderr, "fread failed.\n");
            goto cleanup;
        }
        if (HMAC_Update(hctx, (const unsigned char*)in, inl) != SSL_SUCCESS) {
            fprintf(stderr, "HMAC_Update failed.\n");
            goto cleanup;
        }
        if(inl < BUFF_SIZE)
            break;
    }

    if (HMAC_Final(hctx, hmac, &len) != SSL_SUCCESS) {
        fprintf(stderr, "HMAC_Final failed.\n");
    }

    if (fwrite(hmac, len, 1, outfp) != 1) {
        fprintf(stderr, "fwrite failed.\n");
        goto cleanup;        
    }

cleanup:
    if (hctx !=NULL)
        HMAC_CTX_free(hctx);

    return 0;
}