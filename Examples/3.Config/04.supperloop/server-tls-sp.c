/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"

#include <openssl/ssl.h>

#define SSL_CONTINUE 2

#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111
#define MSG_SIZE            256

/* Print SSL error message */
static void print_SSL_error(const char *msg, SSL *ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
            ERR_error_string(err, NULL));
}

enum
{
    SERVER_BEGIN,
    SERVER_TCP_ACCEPT,
    SERVER_SSL_ACCEPT,
    SERVER_SSL_WRITE,
    SERVER_SSL_READ,
    SERVER_END
};

#define FALLTHROUGH

typedef struct
{
    int stat;
    int sockfd;
    int connd;
    SSL_CTX *ctx;
    SSL *ssl;
} STAT_server;

void stat_init(STAT_server *stat)
{
    stat->stat = SERVER_BEGIN;
    stat->sockfd = -1;
    stat->connd = -1;
    stat->ctx = NULL;
    stat->ssl = NULL;
}

int server_main(STAT_server *stat)
{
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    
    char               buff[MSG_SIZE];
    const char         reply[] = "I hear ya fa shizzle!";
    int                ret = SSL_FAILURE;

    switch (stat->stat) {
    case SERVER_BEGIN:
        /* Initialize library */
        if (SSL_library_init() != SSL_SUCCESS) {
            printf("ERROR: Failed to initialize the library\n");
            goto cleanup;
        }

        /* Create and initialize an SSL context object */
        if ((stat->ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
            fprintf(stderr, "ERROR: failed to create an SSL context object\n");
            goto cleanup;
        }

        /* Load server certificates to the SSL context object */
        if ((ret = SSL_CTX_use_certificate_file(stat->ctx, SERVER_CERT_FILE,
                                                SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load %s\n", SERVER_CERT_FILE);
            goto cleanup;
        }

        /* Load server key into the SSL context object */
        if ((ret = SSL_CTX_use_PrivateKey_file(stat->ctx, SERVER_KEY_FILE,
                                               SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load %s\n", SERVER_KEY_FILE);
            goto cleanup;
        }
        /* 
        * Create a socket, bind and listen
        */
        if ((stat->sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            fprintf(stderr, "ERROR: failed to create a socket. errno %d\n", errno);
            goto cleanup;
        }
        
        fcntl(stat->sockfd, F_SETFL, O_NONBLOCK); /* Non-blocking mode */

        memset(&servAddr, 0, sizeof(servAddr));

        servAddr.sin_family = AF_INET;           /* using IPv4      */
        servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
        servAddr.sin_addr.s_addr = INADDR_ANY;   /* from anywhere   */

        if (bind(stat->sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == -1) {
            fprintf(stderr, "ERROR: failed to bind. errno %d\n", errno);
            goto cleanup;
        }

        stat->stat = SERVER_TCP_ACCEPT;
        printf("Waiting for a connection...\n");

        FALLTHROUGH;
    case SERVER_TCP_ACCEPT:

        if (listen(stat->sockfd, 5) == -1) {
            fprintf(stderr, "ERROR: failed to listen. errno %d\n", errno);
            goto cleanup;
        }
        
        while (1) {
            /* Accept client connections */
            while ((stat->connd = accept(stat->sockfd, (struct sockaddr *)&clientAddr, &size)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return SSL_CONTINUE;
                }
                else if (errno == EINPROGRESS || errno == EALREADY) {
                    break;
                }
                fprintf(stderr, "ERROR: failed to accept %d\n\n", errno);
                ret = SSL_FAILURE;
                goto cleanup;
            }

            /* Create an SSL object */
            if ((stat->ssl = SSL_new(stat->ctx)) == NULL) {
                fprintf(stderr, "ERROR: failed to create an SSL object\n");
                goto cleanup;
            }

            /* Attach the socket to the SSL */
            SSL_set_fd(stat->ssl, stat->connd);

            stat->stat = SERVER_SSL_ACCEPT;
            FALLTHROUGH;
        case SERVER_SSL_ACCEPT:

            /* Establish TLS connection  */
            if ((ret = SSL_accept(stat->ssl)) != SSL_SUCCESS) {
                if (SSL_want(stat->ssl) == SSL_WRITING ||
                    SSL_want(stat->ssl) == SSL_READING) {
                    printf("c");
                    return SSL_CONTINUE;
                }
                print_SSL_error("failed SSL accept", stat->ssl);
                goto cleanup;
            }

            printf("Client connected successfully\n");

            /* 
        * Application messaging
        */
            while (1) {
                stat->stat = SERVER_SSL_READ;
                FALLTHROUGH;
        case SERVER_SSL_READ:
                /* receive a message from the client */
                if ((ret = SSL_read(stat->ssl, buff, sizeof(buff) - 1)) <= 0) {
                    if (SSL_want(stat->ssl) == SSL_READING) {
                        return SSL_CONTINUE;
                    }
                    print_SSL_error("failed SSL read", stat->ssl);
                    break;
                }
                buff[ret] = '\0';
                printf("Received: %s\n", buff);

                /* Check for server shutdown command */
                if (strcmp(buff, "break\n") == 0) {
                    printf("Received break command\n");
                    ret = SSL_SUCCESS;
                    break;
                }

                stat->stat = SERVER_SSL_WRITE;
                FALLTHROUGH;
        case SERVER_SSL_WRITE:
                /* send the reply to the client */
                if ((ret = SSL_write(stat->ssl, reply, sizeof(reply))) < 0) {
                    if (SSL_want(stat->ssl) == SSL_WRITING) {
                        printf("w");
                        return SSL_CONTINUE;
                    }
                    if (ret < 0) {
                        print_SSL_error("failed SSL write", stat->ssl);
                        ret = SSL_FAILURE;
                        break;
                    }
                }
            }

            /* Cleanup after the connection */
            SSL_shutdown(stat->ssl);
            SSL_free(stat->ssl);
            stat->ssl = NULL;
            close(stat->connd);
            stat->connd = -1;
            printf("Closed the connection\n");
        }
    }

/*  Cleanup and return */
cleanup:
    if (stat->ssl != NULL) {
        SSL_shutdown(stat->ssl);
        SSL_free(stat->ssl);
    }
    
    if (stat->sockfd != -1)
        close(stat->sockfd);
    if (stat->ctx != NULL)
        SSL_CTX_free(stat->ctx);
    printf("End of TLS Server\n");
    return ret;
}

int main(int argc, char **argv)
{
    STAT_server stat;

    stat_init(&stat);

    /* Supper Loop */
    while (1)
        if(server_main(&stat) != SSL_CONTINUE)
            break;

}
