/* 
 * client-tls.c
 * Simple Client Program
 */
#include "example_common.h"

#define LOCALHOST           "127.0.0.1"
#define DEFAULT_PORT        11110

#define MSG_SIZE            256

int main(int argc, char **argv)
{
    struct sockaddr_in servAddr;
    int                sockfd = -1;
    char                *ipadd = LOCALHOST;

    char               msg[MSG_SIZE];
    int                ret = 0;

   /* 
    * Set up a TCP Socket and connect to the server 
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create a socket. errno %d\n", errno);
        goto cleanup;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    if ((ret = inet_pton(AF_INET, ipadd, &servAddr.sin_addr)) != 1) {
        fprintf(stderr, "ERROR : failed inet_pton. errno %d\n", errno);
        goto cleanup;
    }
    if ((ret = connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr))) == -1) {
        fprintf(stderr, "ERROR: failed to connect. errno %d\n", errno);
        goto cleanup;
    }

    printf("Message to send: ");
    if(fgets(msg, sizeof(msg), stdin) <= 0)
        goto cleanup;

    /* send a message to the server */
    if ((ret = send(sockfd, msg, strnlen(msg, sizeof(msg)), 0)) < 0) {
        fprintf(stderr, "failed TCP send");
        goto cleanup;
    }

    /* receive a message from the server */
    if ((ret = recv(sockfd, msg, sizeof(msg) - 1, 0)) < 0) {
        fprintf(stderr, "failed TCP recv");
        goto cleanup;
    }
    msg[ret] = '\0';
    printf("Received: %s\n", msg);

/*  Cleanup and return */
cleanup:
    if (sockfd != -1)
        close(sockfd);
    printf("End of TCP Client\n");
    return 0;
}

