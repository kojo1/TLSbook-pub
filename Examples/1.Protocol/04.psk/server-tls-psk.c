/* 
 * server-tls-psk.c
 */
#include "example_common.h"

#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111

#define PSK_KEY_LEN         4

#define MSG_SIZE            256

 /* Identify which psk key to use.                                      */
 /* @param ssl a pointer to SSL object                                  */
 /* @param identity id to identify key                                  */
 /* @param key pre shared key                                           */
 /* @param key_max_len maximum length of the key                        */
 /* @return key length on success, otherwise 0                          */
static unsigned int my_psk_server_cb(SSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    
    printf("Identity: %s\n", identity);
    if (strncmp(identity, "Client_identity", 15) != 0) {
        printf("error!\n");
        return 0;
    }

    key = (unsigned char*)"\x1a\x2b\x3c\x4d";
    if (strlen((const char*)key) < key_max_len) {
        return strlen((const char*)key);
    }
    else {
        return 0;
    }
}

/* Print SSL error message */
static void print_SSL_error(const char *msg, SSL *ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
            ERR_error_string(err, NULL));
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
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto cleanup;
    }

    /* Create and initialize an SSL context object */
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create an SSL context object\n");
        goto cleanup;
    }

    /* use psk suite for security */
    SSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

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
            if (strcmp(buff, "break\n") == 0) {
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
             /* only for SSL_MODE_ENABLE_PARTIAL_WRITE mode */
            if (ret != sizeof(reply)) {
                printf("Partial write\n");
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
