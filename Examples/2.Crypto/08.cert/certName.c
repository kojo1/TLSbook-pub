
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

int main(int argc, char **argv)
{
    X509_NAME_ENTRY *ne = NULL;
    X509_NAME* name     = NULL;
    X509* x509          = NULL;
    ASN1_STRING* asn    = NULL;
    char* subCN         = NULL;
    int idx;

    if(argc != 2)
        printf("Usage: certName <PEM file>\n");

    if((x509 = X509_load_certificate_file(argv[1], WOLFSSL_FILETYPE_PEM)) == NULL) {
        fprintf(stderr, "X509_load_certificate_file\n");
        goto cleanup;
    }
    if((name = X509_get_subject_name(x509)) == NULL) {
        fprintf(stderr, "X509_get_subject_name\n");
        goto cleanup;
    }

    if((idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1))  == -1)
    {
        fprintf(stderr, "X509_NAME_get_index_by_NID\n");
        goto cleanup;
    }
    if((ne = X509_NAME_get_entry(name, idx)) == NULL) {
        fprintf(stderr, "X509_NAME_get_entry\n");
        goto cleanup;
    }
    if((asn = X509_NAME_ENTRY_get_data(ne)) == NULL) {
        fprintf(stderr, "X509_NAME_ENTRY_get_data\n");
        goto cleanup;
    }
    if((subCN = (char*)ASN1_STRING_data(asn)) == NULL) {
        fprintf(stderr, ")ASN1_STRING_data\n");
        goto cleanup;
    }
    
    printf("CN: %s\n", subCN);

cleanup:
    X509_free(x509);

}
