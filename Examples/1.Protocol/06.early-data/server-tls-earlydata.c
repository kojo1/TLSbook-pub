/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"


#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111
#define MSG_SIZE            256
#define MAX_EARLYDATA_SZ    32

/* Print SSL error message */
static void print_SSL_error(const char *msg, SSL *ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
            ERR_error_string(err, NULL));
}
/* read early data */
static void ReadEarlyData(SSL* ssl)
{
    int ret;
    int err;
    size_t len;
    char early_data[32];
    
    (void)err;

        do {
            err = 0;
            len = 0;
            ret = SSL_read_early_data(ssl, early_data, sizeof(early_data)-1, &len);
            if (ret <= 0) {
                err = SSL_get_error(ssl, 0);
            }
            
            if (len > 0) {
                early_data[len] = '\0'; 
                printf("Early Data Client message: %s\n", early_data);
            }
        } while(ret > 0);
}

int main(int argc, char** argv)
{
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    int                sockfd = -1;
    int                connd = -1;
    
    char               buff[MSG_SIZE];
    const char         reply[] = "I hear ya fa shizzle!";
    int                ret = SSL_FAILURE;

    /* Declare SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

    /* Initialize library */
    if (SSL_library_init() != SSL_SUCCESS) {
        printf("ERROR: Failed to initialize the library\n");
        goto cleanup;
    }

    /* Create and initialize an SSL context object */
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create an SSL context object\n");
        goto cleanup;
    }

    /* Load server certificates to the SSL context object */
    if ((ret = SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, 
        SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s\n", SERVER_CERT_FILE);
        goto cleanup;
    }

    /* Load server key into the SSL context object */
    if ((ret = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, 
        SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s\n", SERVER_KEY_FILE);
        goto cleanup;
    }
    /* 
    * Create a socket, bind and listen
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create a socket. errno %d\n", errno);
        goto cleanup;
    }
    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind. errno %d\n", errno);
        goto cleanup;
    }

    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen. errno %d\n", errno);
        goto cleanup;
    }

    while (1) {
        printf("Waiting for a connection...\n");
        
        /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) {
            fprintf(stderr, "ERROR: failed to accept. errno %d\n", errno);
            goto cleanup;
        }
        
        /* Create an SSL object */
        if ((ssl = SSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create an SSL object\n");
            goto cleanup;
        }
        /* Attach the socket to the SSL */
        SSL_set_fd(ssl, connd);

        /* set maximum early data for write */
        if ((ret = SSL_set_max_early_data(ssl, MAX_EARLYDATA_SZ))
                != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: Failed to set maximum early data for write\n");
            goto cleanup;
        }

       /* check early data */
        ReadEarlyData(ssl);
       
       /* Establish TLS connection  */
        if ((ret = SSL_accept(ssl)) != SSL_SUCCESS) {
            print_SSL_error("failed SSL accept", ssl);
            goto cleanup;
        }
        
        printf("Client connected successfully\n");
        
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
            printf("Received: %s\n", buff);

            /* Check for server shutdown command */
            if (strcmp(buff, "break") == 0) {
                printf("Received break command\n");
                break;
            }

            /* send the reply to the client */
            if ((ret = SSL_write(ssl, reply, sizeof(reply))) < 0) {
                if (ret < 0) {
                    print_SSL_error("failed SSL write", ssl);
                    ret = SSL_FAILURE;
                    break;
                }
            }
        }

        /* Cleanup after the connection */
        SSL_shutdown(ssl);
        SSL_free(ssl); 
        ssl = NULL;
        close(connd);
        connd = -1;
        printf("Closed the connection\n");
    }

/*  Cleanup and return */
cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    
    if (sockfd != -1)
        close(sockfd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ret != SSL_SUCCESS)
        ret = SSL_FAILURE;
    printf("End of TLS Server\n");
    return ret;
}
