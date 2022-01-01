/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"

#include <openssl/ssl.h>
#include "file-comm.h"

#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define MSG_SIZE            256

/* Print SSL error message */
static void print_SSL_error(const char *msg, SSL *ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "\t\t\t\t\tERROR: %s (err %d, %s)\n", msg, err,
            ERR_error_string(err, NULL));
}

int main(int argc, char** argv)
{   
    char               buff[MSG_SIZE];
    const char         reply[] = "I hear ya fa shizzle!";
    int                ret = SSL_FAILURE;

    /* Declare SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

    /* Create and initialize an SSL context object */
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        fprintf(stderr, "\t\t\t\t\tERROR: failed to create an SSL context object\n");
        goto cleanup;
    }

    /* Load server certificates to the SSL context object */
    if ((ret = SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, 
        SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "\t\t\t\t\tERROR: failed to load %s\n", SERVER_CERT_FILE);
        goto cleanup;
    }

    /* Load server key into the SSL context object */
    if ((ret = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, 
        SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "\t\t\t\t\tERROR: failed to load %s\n", SERVER_KEY_FILE);
        goto cleanup;
    }

    /* Register callbacks */
    wolfSSL_SetIORecv(ctx, fileCbIORecv);
    wolfSSL_SetIOSend(ctx, fileCbIOSend);

    while (1) {
        printf("\t\t\t\t\tWaiting for a connection...\n");

        /* Create an SSL object */
        if ((ssl = SSL_new(ctx)) == NULL) {
            fprintf(stderr, "\t\t\t\t\tERROR: failed to create an SSL object\n");
            goto cleanup;
        }

        frecv = open(C2S, O_CREAT | O_RDONLY | O_NOCTTY | O_TRUNC);
        fsend = open(S2C, O_CREAT | O_WRONLY | O_NOCTTY | O_TRUNC);
        wolfSSL_SetIOReadCtx(ssl, &frecv);
        wolfSSL_SetIOWriteCtx(ssl,&fsend);

        /* Establish TLS connection  */
        if ((ret = SSL_accept(ssl)) != SSL_SUCCESS) {
            print_SSL_error("failed SSL accept", ssl);
            goto cleanup;
        }

        /* 
        * Application messaging
        */
        while(1) {

            /* receive a message from the client */
            if ((ret = SSL_read(ssl, buff, sizeof(buff)-1)) <= 0) {
                print_SSL_error("failed SSL read", ssl);
                break;
            }
            buff[ret] = '\0';
            printf("\t\t\t\t\tReceived: %s\n", buff);

            /* Check for server shutdown command */
            if (strcmp(buff, "break\n") == 0) {
                printf("\t\t\t\t\tReceived break command\n");
                goto cleanup;
            }

            /* send the reply to the client */
            if ((ret = SSL_write(ssl, reply, sizeof(reply))) < 0) {
                if (ret < 0) {
                    print_SSL_error("failed SSL write", ssl);
                    ret = SSL_FAILURE;
                    break;
                }
            }
             /* only for SSL_MODE_ENABLE_PARTIAL_WRITE mode */
            if (ret != sizeof(reply)) {
                printf("\t\t\t\t\tPartial write\n");
            }
        }

        /* Cleanup after the connection */
        SSL_shutdown(ssl);
        SSL_free(ssl); 
        ssl = NULL;
        printf("\t\t\t\t\tClosed the connection\n");
    }

/*  Cleanup and return */
cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ret != SSL_SUCCESS)
        ret = SSL_FAILURE;
    printf("\t\t\t\t\tEnd of TLS Server\n");
    return ret;
}
