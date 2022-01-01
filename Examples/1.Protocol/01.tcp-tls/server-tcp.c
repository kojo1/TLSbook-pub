/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"

#define DEFAULT_PORT        11110
#define MSG_SIZE            256

int main(int argc, char** argv)
{
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    int                sockfd = -1;
    int                connd = -1;
    
    char               buff[MSG_SIZE];
    const char         reply[] = "I hear ya fa shizzle!";
    int                ret = 0;

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

    printf("Waiting for a connection...\n");
    
    /* Accept client connections */
    if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) {
        fprintf(stderr, "ERROR: failed to accept. errno %d\n", errno);
        goto cleanup;
    }
    
    printf("Client connected successfully\n");

    /* receive a message from the client */
    if ((ret = recv(connd, buff, sizeof(buff)-1, 0)) <= 0) {
        fprintf(stderr, "failed TCP read");
        goto cleanup;
    }
    buff[ret] = '\0';
    printf("Received: %s\n", buff);

    /* send the reply to the client */
    if ((ret = send(connd, reply, sizeof(reply), 0)) < 0) {
        if (ret < 0) {
            fprintf(stderr, "failed TCP write");
            goto cleanup;
        }
    }
    
    /* Cleanup after the connection */
    close(connd);
    connd = -1;
    printf("Closed the connection\n");

/*  Cleanup and return */
cleanup:
    if (sockfd != -1)
        close(sockfd);
    printf("End of TCP Server\n");
    return 0;
}
