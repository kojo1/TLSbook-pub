

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

int algo_main(int mode, FILE *fpKey, FILE *fpDec,
              unsigned char *key, int key_sz,
              unsigned char *iv, int iv_sz,
              unsigned char *tag, int tag_sz)
{
    /***
        infp: RSA key in DER for Decrypt
        stdin: Message to Decrypt
        outfp: Decrypted message
    ***/

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

#define KEY_SIZE 2048
    unsigned char key_buff[KEY_SIZE];
    const unsigned char *p = key_buff;
#define DEC_SIZE 256
    unsigned char dec[DEC_SIZE];
#define BUFF_SIZE 512
    unsigned char msg[BUFF_SIZE];
    size_t dec_sz;
    size_t msg_sz;
    int ret = SSL_FAILURE;

    /* Check arguments */
    if (mode >= 0 || fpKey == NULL || fpDec == NULL || tag != NULL || key != NULL || iv != NULL)
    {
        fprintf(stderr, "ERROR: command argment\n");
        return ret;
    }

    /* End argment check */

    if ((msg_sz = fread(msg, 1, BUFF_SIZE, stdin)) < 0)
    {
        fprintf(stderr, "ERROR: fread\n");
        goto cleanup;
    }

    if ((key_sz = fread(key_buff, 1, sizeof(key_buff), fpKey)) < 0)
    {
        fprintf(stderr, "ERROR: read key\n");
        return ret;
    }

    if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, key_sz)) == NULL)
    {
        fprintf(stderr, "ERROR: d2i_PublicKey\n");
        goto cleanup;
    }

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL)
    {
        fprintf(stderr, "ERROR: EEVP_PKEY_CTX_new\n");
        goto cleanup;
    }

    if (EVP_PKEY_decrypt_init(ctx) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: EVP_PKEY_encrypt_init\n");
        goto cleanup;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: EVP_PKEY_CTX_set_rsa_padding\n");
        goto cleanup;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, &dec_sz, msg, msg_sz) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: EVP_PKEY_encrypt\n");
        goto cleanup;
    }
    if (DEC_SIZE != dec_sz)
    {
        fprintf(stderr, "ERROR: Message size error\n");
        goto cleanup;
    }

    if (EVP_PKEY_decrypt(ctx, dec, &dec_sz, (const unsigned char *)msg, msg_sz) != SSL_SUCCESS)
    {
        fprintf(stderr, "ERROR: EVP_PKEY_encrypt\n");
        goto cleanup;
    }

    if (fwrite(dec, 1, dec_sz, fpDec) != dec_sz)
    {
        fprintf(stderr, "ERROR: fwrite\n");
        goto cleanup;
    }
    ret = SSL_SUCCESS;

cleanup:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    return ret;
}
