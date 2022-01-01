

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#define HASH EVP_sha256()

int algo_main(int mode, FILE *fpKey, FILE *fpSig,
              unsigned char *key, int key_sz,
              unsigned char *iv, int iv_sz,
              unsigned char *tag, int tag_sz)
{
    /***
        infp: EC key in DER for sign
        stdin: Message to sign
        outfp: ECDSA Signature
    ***/

    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;

#define KEY_SIZE 256
    unsigned char key_buff[KEY_SIZE];
    const unsigned char *key_p = key_buff;
#define SIG_SIZE 256
    unsigned char sig[SIG_SIZE];
#define BUFF_SIZE 256
    unsigned char msg[BUFF_SIZE];
    int inl;
    size_t sig_sz;
    int ret = SSL_FAILURE;

    /* Check arguments */
    if (mode >= 0 || fpKey == NULL || fpSig == NULL || tag != NULL || key != NULL || iv != NULL)
    {
        fprintf(stderr, "ERROR: command argment\n");
        return ret;
    }

    /* End argment check */

    if ((key_sz = fread(key_buff, 1, sizeof(key_buff), fpKey)) < 0)
    {
        fprintf(stderr, "ERROR: read key\n");
        return ret;
    }

    if ((pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &key_p, key_sz)) == NULL)
    {
        fprintf(stderr, "ERROR: d2i_PrivateKey\n");
        return ret;
    };

    if ((md = EVP_MD_CTX_new()) == NULL)
    {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new\n");
        goto cleanup;
    };

    if (EVP_DigestSignInit(md, NULL, HASH, NULL, pkey) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        goto cleanup;
    }


    while (1) {
        if ((inl = fread(msg, 1, BUFF_SIZE, stdin)) < 0) {
            fprintf(stderr, "ERROR: fread\n");
            goto cleanup;
        }
        if (inl < BUFF_SIZE)
            break;
        EVP_DigestSignUpdate(md, msg, inl);
    }

    EVP_DigestSignFinal(md, sig, &sig_sz);
    if (fwrite(sig, 1, sig_sz, fpSig) != sig_sz)
    {
        fprintf(stderr, "ERROR: fwrite\n");
        goto cleanup;
    }
    ret = SSL_SUCCESS;

cleanup:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (md != NULL)
        EVP_MD_CTX_free(md);

    return ret;
}
