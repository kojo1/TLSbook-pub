

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#define HASH EVP_sha256()

int main(int argc, char **argv)
{
    X509 *caX509 = NULL;
    X509 *svrX509 = NULL;
    X509_STORE_CTX *storeCtx = NULL;
    X509_STORE *store     = NULL;
    X509_NAME *subject    = NULL;
    STACK_OF(X509) *certs = NULL;

    if(argc != 3) {
        fprintf(stderr, "Usage: x509cert CAfile certFile\n");
        goto cleanup;
    }

    if((store = X509_STORE_new()) == NULL) {
        fprintf(stderr, "ERROR: X509_STORE_new\n");
        goto cleanup;
    }

    if((caX509 = X509_load_certificate_file(argv[1], SSL_FILETYPE_PEM)) == NULL) {
        fprintf(stderr, "ERROR: X509_load_certificate_file(%s)\n", argv[1]);
        goto cleanup;
    }
    if((svrX509 = X509_load_certificate_file(argv[2], SSL_FILETYPE_PEM)) == NULL) {
        fprintf(stderr, "ERROR: X509_load_certificate_filen(%s)", argv[2]);
        goto cleanup;
    }
    if((storeCtx = X509_STORE_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: X509_STORE_CTX_new\n");
        goto cleanup;
    }

    if((subject = X509_get_subject_name(caX509)) == NULL) {
        fprintf(stderr, "ERROR: X509_get_subject_name\n");
        goto cleanup;
    }

    if((certs = X509_STORE_get1_certs(storeCtx, subject)) == NULL) {
        fprintf(stderr, "ERROR: X509_STORE_get1_certs\n");
        goto cleanup;
    }

    if(sk_X509_num(certs) != 1) {
        fprintf(stderr, "ERROR: sk_X509_num(\n");
        goto cleanup;
    }

    sk_X509_pop_free(certs, NULL);

cleanup:
    X509_STORE_free(store);
    X509_STORE_CTX_free(storeCtx);
    X509_free(svrX509);
    X509_free(caX509);
}
