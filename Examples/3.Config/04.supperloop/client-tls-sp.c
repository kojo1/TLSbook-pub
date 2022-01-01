/* 
 * client-tls.c
 * Simple Client Program
 */
#include "example_common.h"

#include <openssl/ssl.h>

#define SSL_CONTINUE 2

#define CA_CERT_FILE        "../../certs/tb-ca-cert.pem"
#define LOCALHOST           "127.0.0.1"
#define DEFAULT_PORT        11111

#define MSG_SIZE            256

/* Print SSL error message */
static void print_SSL_error(const char* msg, SSL* ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
                    ERR_error_string(err, NULL));
}

enum
{
    CLIENT_BEGIN,
    CLIENT_TCP_CONNECT,
    CLIENT_SSL_CONNECT,
    CLIENT_SSL_WRITE,
    CLIENT_SSL_READ,
    CLIENT_END
};

#define FALLTHROUGH

typedef struct {
    int stat;
    int sockfd;
    char ipadd[32];
    SSL_CTX *ctx;
    SSL *ssl;
} STAT_client;

void stat_init(STAT_client *stat)
{
    stat->stat = CLIENT_BEGIN;
    stat->sockfd = -1;
    stat->ctx    = NULL;
    stat->ssl    = NULL;
}

int client_main(STAT_client *stat)
{

    struct sockaddr_in servAddr;

    static char    msg[MSG_SIZE];
    int     ret = SSL_FAILURE;

    switch(stat->stat) {
    case CLIENT_BEGIN:
        /* Initialize library */
        if (SSL_library_init() != SSL_SUCCESS) {
            printf("ERROR: failed to initialize the library\n");
            goto cleanup;
        }
        /* Create and initialize an SSL context object*/
        if ((stat->ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
            fprintf(stderr, "ERROR: failed to create an SSL context object\n");
            goto cleanup;
        }
        /* Load CA certificate to the context */
        if ((ret = SSL_CTX_load_verify_locations(stat->ctx, CA_CERT_FILE, NULL)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load %s \n", CA_CERT_FILE);
            goto cleanup;
        }

        /* 
        * Set up a TCP Socket and connect to the server 
        */
        if ((stat->sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            fprintf(stderr, "ERROR: failed to create a socket. errno %d\n", errno);
            goto cleanup;
        }

        fcntl(stat->sockfd, F_SETFL, O_NONBLOCK); /* Non-blocking mode */

        memset(&servAddr, 0, sizeof(servAddr));
        servAddr.sin_family = AF_INET;           /* using IPv4      */
        servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
        if ((ret = inet_pton(AF_INET, stat->ipadd, &servAddr.sin_addr)) != 1) {
            fprintf(stderr, "ERROR : failed inet_pton. errno %d\n", errno);
            goto cleanup;
        }

        stat->stat = CLIENT_TCP_CONNECT;
        FALLTHROUGH;
    case CLIENT_TCP_CONNECT:
        while ((ret = connect(stat->sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr))) == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return SSL_CONTINUE;
            }
            else if (errno == EINPROGRESS || errno == EALREADY) {
                break;
            }
            fprintf(stderr, "ERROR: failed to connect %d\n\n", errno);
            ret = SSL_FAILURE;
            goto cleanup;
        }

        /* Create a WOLFSSL object */
        if ((stat->ssl = wolfSSL_new(stat->ctx)) == NULL) { 
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            goto cleanup;
        }

        /* Attach the socket to the SSL */
        if ((ret = SSL_set_fd(stat->ssl, stat->sockfd)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
            goto cleanup;
        }

        stat->stat = CLIENT_SSL_CONNECT;
        FALLTHROUGH;
    case CLIENT_SSL_CONNECT:

        /* SSL connect to the server */
        if ((ret = SSL_connect(stat->ssl)) != SSL_SUCCESS) {
            if (SSL_want(stat->ssl) == SSL_WRITING ||
                SSL_want(stat->ssl) == SSL_READING){             
                return SSL_CONTINUE;
            }
            print_SSL_error("failed SSL connect", stat->ssl);
            goto cleanup;
        }
        printf("\n");

        /* 
        * Application messaging
        */
        while (1) {

            printf("Message to send: ");
            if(fgets(msg, sizeof(msg), stdin) <= 0)
                break;

            /* send a message to the server */
            stat->stat = CLIENT_SSL_WRITE;
            FALLTHROUGH;
    case CLIENT_SSL_WRITE:

        if ((ret = SSL_write(stat->ssl, msg, strlen(msg))) < 0){
            if (SSL_want(stat->ssl) == SSL_WRITING){
                return SSL_CONTINUE;
            }
            print_SSL_error("failed SSL write", stat->ssl);
            goto cleanup;
        }
        printf("\n");
        if (strcmp(msg, "break\n") == 0) {
            printf("Sending break command\n");
            ret = SSL_SUCCESS;
            goto cleanup;
        }

        stat->stat = CLIENT_SSL_READ;
        FALLTHROUGH;
    case CLIENT_SSL_READ:

            /* receive a message from the server */
            if ((ret = SSL_read(stat->ssl, msg, sizeof(msg) - 1)) < 0) {
                if (SSL_want(stat->ssl) == SSL_READING){
                    return SSL_CONTINUE;
                }
                print_SSL_error("failed SSL read", stat->ssl);
                goto cleanup;
            }
            printf("\n");
            msg[ret] = '\0';
            printf("Received: %s\n", msg);
            ret = SSL_CONTINUE;
        }
    }


/*  Cleanup and return */
cleanup:

    stat->stat = CLIENT_END;

    if (stat->ssl != NULL) {
        SSL_shutdown(stat->ssl);
        SSL_free(stat->ssl);
    }
    if (stat->ctx != NULL)
        SSL_CTX_free(stat->ctx);
    if (stat->sockfd >= 0)
        close(stat->sockfd);
    printf("End of TLS Client\n");
    stat->stat = CLIENT_BEGIN;
    return ret;
}

int main(int argc, char **argv)
{
    STAT_client stat;

    /* Check for proper calling convention */
    if (argc == 2) {
        strcpy(stat.ipadd, argv[1]);
    }
    else if (argc == 1) {
        printf("Send to localhost(%s)\n", LOCALHOST);
        strcpy(stat.ipadd, LOCALHOST);
    } else {
        printf("ERROR: Too many arguments.\n");
        return -1;
    }

    stat_init(&stat);

    /* Supper Loop */
    while(1)
        if(client_main(&stat) != SSL_CONTINUE)
            break;

    return 0;
}