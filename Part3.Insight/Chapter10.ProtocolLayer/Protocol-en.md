## Chapter 10 Protocol Processing

### 10.1 TLS connection

As mentioned above, the TLS protocol processing unit is layered into three layers: protocol state transition management, handshake message processing, and TLS record processing. Figure 9-2 shows the process flow using the wolfSSL_connect function as an example.

As introduced in Chapter 2, the TLS handshake protocol has changed significantly between TLS 1.2 and TLS 1.3. Therefore, protocol state transition management also branches depending on the target version at the entrance of the wolfSSL_connect function, and in the case of TLS1.3, it is processed by the wolfSSL_connect_TLSv13 function. If it is TLS1.2 or earlier, it will be processed by the wolfSSL_connect function as it is. The figure shows the flow for TLS1.3, but in both cases the state is managed by a switch statement, and the handshake state flows from the upper case to the lower case. In each case, if the processing is normal, the next state is set, and the processing of the next case is directly entered without breaking. In case of an error, the function is returned as an error by immediately performing appropriate error processing such as alert processing.

In this way, in the normal processing mode, the switch statement merely indicates the transition of the state and does not play a major role, but when operating in the non-block mode, the switch statement jumps to the appropriate case statement according to the state and processes it. To proceed. The non-block mode processing will be described later.


<br> <br>
![Fig. 9-2](./fig9-2.png)
<br> <br>

The following program extracts only the first half of the protocol state transition from the source code of the wolfSSL_connect_TLSv13 function.


```
int wolfSSL_connect_TLSv13 (WOLFSSL * ssl)
{
    switch (ssl-> options.connectState) {
        case CONNECT_BEGIN:
            / * Always send client hello first. * /
            if ((ssl-> error = SendTls13ClientHello (ssl))! = 0) {
                WOLFSSL_ERROR (ssl-> error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl-> options.connectState = CLIENT_HELLO_SENT;
            FALL_THROUGH;
        case CLIENT_HELLO_SENT:
            / * Get the response / s from the server. * /
            while (ssl-> options.serverState <
                                          SERVER_HELLO_RETRY_REQUEST_COMPLETE) {
                if ((ssl-> error = ProcessReply (ssl)) <0) {
                    WOLFSSL_ERROR (ssl-> error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            ssl-> options.connectState = HELLO_AGAIN;
            FALL_THROUGH;
        case HELLO_AGAIN:
            if (ssl-> options.serverState ==
                                          SERVER_HELLO_RETRY_REQUEST_COMPLETE) {
                / * Try again with different security parameters. * /
                if ((ssl-> error = SendTls13ClientHello (ssl))! = 0) {
                    WOLFSSL_ERROR (ssl-> error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            ssl-> options.connectState = HELLO_AGAIN_REPLY;
            FALL_THROUGH
            ...
```


Procol state transitions are managed for each SSL session. The SSL structure ssl-> options.connectState is the state variable. In coding, the entire state transition is surrounded by a switch statement and separated by a case statement corresponding to the state, but there is no break statement at the end of each case statement and the process flows to the next case as it is. It is coded as FALL_THROUGH to make it explicit, but it is defined as a blank macro that does nothing by itself. This switch statement works in non-blocking mode, which we'll discuss in the next section. In the blocking mode, the process simply progresses from top to bottom in this switch statement with the state transition.

The state starts with CONNECT_BEGIN. In this state, the function calls the SendClientHello function. SendClientHello configures ClientHello for the first message of the handshake and sends it as a TLS record with the SendBuffered function. When the transmission is completed normally, set the status to the next CLIENT_HELLO_SENT and wait for the response from the server with the ProcessReply function.

The ProcessReply function waits for the TLS record from the server to be received. After checking the validity of the received TLS record, if the handshake message is expected, call the corresponding message processing function. In this case, call the DoServerHallo function to process the received message.

After transitioning to the handshake state in this way and finally sending the Finished message normally, it will be in the FINISHED_DONE state and the wolfSSL_Connect function will return normally.


### 10.2 Non-blocking mode

The same library code works in non-blocking mode as well. When wolfSSL_connect (in which wolfSSL_connect_TLSv13) is called, in the initial state, SendTls13ClientHello is called from CONNECT_BEGIN by the switch statement, SendBuffered is called to send the TLS record, and the message is buffered and returned normally. When the SendTls13ClientHello function completes normally, the following state CLIENT_HELLO_SENT is set, the ProcessReply function is called, and finally the socket recv function is called. If the Socket is in non-blocking mode, the recv function returns immediately even if no response message has been received from the server.

At this time, EWOULDBLOCK, which indicates that the return is non-blocking processing, is returned as the return value. This is internally translated as WANT_READ, which is one of the error codes, and this code is returned as the return value of the ProcessReply function. Within wolfSSL_connect, this return value is set to a detailed error code and the function returns with the same return value WOLFSSL_FATAL_ERROR as the error termination.

On the application side that called the wolfSSL_connect function, if the return value of the function is WOLFSSL_FATAL_ERROR, and if the detailed error is either WANT_WRITE or WANT_READ, it is determined that the non-blocking process has returned to normal (in some cases, via a super loop, etc.). ) Call the wolfSSL_connect function repeatedly.

In the called wolfSSL_connect again, the protocol state is CLIENT_HELLO_SENT and ProcessReply will be called again. If a response message from the server is received when the ProcessReply is called several times, the socket recv function returns the message, so the contents are parsed in ProcessReplay and the appropriate handshake process is called. In this case, when DoServerHello is called and the process is completed normally, the function returns with the return value of normal termination. Since it ended normally, it transitions to the next state and the next processing is performed.

In this way, every time a blocking state such as message reception is encountered in the wolfSSL_connect function, WOLFSSL_FATAL_ERROR is returned as the return value of the function, and WANT_WRITE or WANT_READ is returned as the detailed error, so the caller should repeatedly call the wolfSSL_connect function. The state of the protocol will be advanced. When all the handshakes are finally completed and the state transitions to the FINISHED_DONE state, the normal end is returned as the return value of the function, so the application side knows that the entire handshake process has been completed normally.

In this way, in non-blocking processing, the error value is used as the return value of the function at the time of non-blocking processing, and by discriminating the non-blocking processing by the detailed error, the non-blocking processing is realized with the same code as in the blocking mode. Both non-blocking mode and blocking mode must be realized in the socket layer or application layer for timeout.