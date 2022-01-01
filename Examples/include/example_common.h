/*
* common header file
*/
#ifndef _EXAMPLE_COMMON_H_
#define _EXAMPLE_COMMON_H_

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifndef SSL_SUCCESS
#define SSL_SUCCESS 1
#endif
#ifndef SSL_FAILURE
#define SSL_FAILURE 0
#endif

/* MyKeyLog_cb is a callback function for wolfSSL_CTX_set_keylog_callback.
 * Opens SSLKEYLOGFILE file and appends key logs to it. The file is intended to
 * be configured in WireShark to decode encripted handshake packets.
 * 
 * Steps to configure WireShark:
 * 1. Run WireShark and go to Edit > Preferences > Protocols > TLS.
 * 2. You can see (Pre)-Master-Secret log filename text box in the pain.
 * 3. Fill it with the full file path defined as SSLKEYLOGFILE.
 * 4. Start capture.   
 */
#if defined(SSLKEYLOGFILE)
static void MyKeyLog_cb(const SSL* ssl, const char* line)
{
    FILE* fp;
    const byte  lf = '\n';
    (void)ssl;

    fp = fopen(SSLKEYLOGFILE, "a");
    fwrite(line, 1, strlen(line), fp);
    fwrite((void*)&lf, 1, 1, fp);
    fclose(fp);
}
#endif /* SSLKEYLOGFILE */

#endif /* _EAMPLE_COMMON_H_ */
