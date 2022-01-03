# 7. Cryptographic algorithm

This chapter introduces sample programs for various cryptographic algorithms.

## 7.1 Common wrapper
The programs in this chapter provide a main function that acts as a common wrapper so that it acts as a command. Its contents are stored in common / main.c. The main function in main.c checks and parses a series of arguments and calls the algo_main function.
The algo_main function is a separate function for each algorithm sample. By using this wrapper, the functions of the individual algorithms can only do the specific processing for the algorithm.

Commands using this wrapper function accept the following arguments.

- First argument: File name (default input, optional)
- Second argument: File name (default output, optional)

The following optional arguments:
- e: Encryption process
- d: Decryption process
- k: Specify the hexadecimal key value in the next argument
- i: Specify hexadecimal IV value in the next argument
- t: Specify the hexadecimal tag value in the next argument

The algo_main function is defined in main.h as follows: The main function in main.c inherits the analysis content of the argument to the argument of the algo_main function.

```
void algo_main (int mode, FILE * fp1, FILE * fp2,
                 unsigned char * key, int key_sz,
                 unsigned char * iv, int iv_sz,
                 unsigned char * tag, int tag_sz
                );
```

The file specified by the first and second arguments is fopened and inherited by the file descriptors fp1 and fp2. The default open mode is "rb" for fp1 and "wb" for fp2. To change it, define an arbitrary mode character string in the Makefile with the macro names OPEN_MODE1 and OPEN_MODE2 defined at compile time.

If opening fails, an error message will be output in main.c and algo_main will not be called.
If the argument is omitted, NULL is passed to fp1 and fp2.


As a wrapper, the mode indicated by -e, -d, and the hexadecimal value of any length specified by -k, -i, -t are passed to algo_main. If an invalid hexadecimal string is detected, an error will be output in the main function and algo_main will not be called. Nulls are passed to the pointer value for optional argument that is not specified. Check each algo_main to see if the option augments are needed and the size is appropriate.

### Buffer size
The cryptographic API used in the sample can process at once with a buffer as large as the memory size allows, but the buffer size is intentionally set to show an example of processing large size data by repeating small processing units. I am limiting. The definition of "#define BUFF_SIZE" near the beginning of the source code of each algorithm can be changed as appropriate.


## 7.2 Hash

#### 1) Overview
This sample program finds the hash value for a given message of arbitrary length. The program asks for the SHA256 hash value as an example.

#### 2) Commands and usage examples

The hash value (binary value) of the message stored in msg.txt is output to hash.bin, and the output value is dumped in hexadecimal.

```
$ ./sha256 msg.txt hash.bin
$ hexdump! $
hexdump hash.bin
0000000 c4 e8 fe 54 5d 7c fd b0 07 aa 51 0e 6b 98 d7 7d
0000010 c2 3f e0 f6 75 0f a8 42 08 92 ea 41 96 f5 03 24
0000020
```

Find the hash value of the same file with the OpenSSL dgst subcommand and make sure they are the same.

```
$ openssl dgst -sha256 msg.txt
SHA256 (msg.txt) = c4e8fe545d7cfdb007aa510e6b98d77dc23fe0f6750fa8420892ea4196f50324
```

#### 3) Program


The program takes up to two arguments. The first argument gives the input data file path that stores the input data. The second argument is the file path to which the hash data is output. The second argument is optional and if not specified, the hash data will be output to standard output. The size of the input data given is arbitrary. In the case of SHA256, the output hash data is output as 32-byte binary data.

OpenSSL / wolfSSL provides a series of functions starting with "EVP_MD_CTX" and "EVP_Digest" to obtain a hash (message digest) of the given data. The hash algorithm to be executed is specified when initializing with the EVP_DigestInit function.

Prepare a management block for the processing context at the beginning of the process (EVP_MD_CTX_init). Next, specify the hash algorithm for the context prepared by the "EVP_DigestInit" function. In this example, SHA256 is specified. Other hashes by modifying this part according to the table below
You can process the algorithm.

Hash processing is performed by the "EVP_DigestUpdate" function. If the memory size limit allows, the entire input data can be passed to the "EVP_DigestUpdate" function at once, but if there is a limit, divide it into appropriate sizes and use the "EVP_DigestUpdate" function.
You can also call it multiple times.

Finally, the "EVP_DigestFinal" function outputs the hash value stored in the context to the buffer, and then the file,
Alternatively, output to standard output and exit.
<br>

| Function name | Function |
| --- | --- |
| EVP_MD_CTX_new | Hash processing context secured |
EVP_MD_CTX_free | Free hash processing context |
| EVP_DigestInit | Initialize context by specifying hash type |
| EVP_DigestUpdate | Added target message. Can be called repeatedly |
| EVP_DigestFinal | Find the hash value |

Table: Basic functions for hashing


The main algorithms that can be specified with EVP_DigestInit are summarized in the table below.

| Algorithm | Initialization function name |
| --- | --- |
MD5 | EVP_md5 |
| Sha1 | EVP_sha1 |
| Sha224 | EVP_sha224 |
| Sha256 | EVP_sha256 |
| Sha384 | EVP_sha384 |
| Sha512 | EVP_sha512 |
| Sha512 / 224 | EVP_sha512_224 |
| Sha512 / 256 | EVP_sha512_256 |
| Sha3 / 224 | EVP_sha3_224 |
| Sha3 / 256 | EVP_sha3_256 |
| Sha3 / 284 | EVP_sha3_384 |
| Sha3 / 512 | EVP_sha3_512 |

Table: Main hash algorithms that can be specified with EVP_DigestInit
<br>

# 7.3 Message authentication code

### 1) Overview

OpenSSL / wolfSSL provides the following set of functions starting with "HAC" to generate a message authentication code with the given data together with the key. This section provides examples of programs that use this HMAC function.

This sample program finds the HMAC value for a given message of arbitrary length.
The message authentication code is generated by synthesizing the input data and key data and then hashing them using the specified hash algorithm. At the beginning of the process
Select the hash algorithm to get the message digest structure. After that, secure the management block "HMAC_CTX" as the processing context. Next, the message digest structure and the key data to be combined with the data to be hashed are given to the context secured by the initialization function by the "Init" function, and initialization is executed.

Hashing is done by the "HMAC_Update" function. If the memory size limit allows, the entire input data can be passed to the "Update" function at once, but if there is a limit, the "Update" function can be called multiple times by dividing it into appropriate sizes. increase. Finally, the "Final" function outputs the hash value (message authentication code) stored in the context to the buffer and writes it to a file.

This program uses "SHA1" as the hash algorithm. You can specify the hash algorithm by passing the message digest structure (EVP_MD) with the hash algorithm set to the HMAC initialization function. To get the message digest structure, specify the character string indicating the algorithm in the EVP_get_digestbyname function. The table below shows an example of the hash algorithm string that can be specified for the EVP_get_digestbyname function.

#### 2) Commands and usage examples

This program accepts the following command agreements:

--Input file: Uses the file with the specified file name as input data.
--Output file: Outputs the result data to the file with the specified file name. If omitted, output to standard output.
--Specify the key value in hexadecimal in the next argument after "-k". You need to specify at least 1 byte.

The hash algorithm used in this program uses "SHA1". You can specify the hash algorithm by passing the message digest structure (EVP_MD) with the hash algorithm set to the HMAC initialization function described later.

The hash value (binary value) of the message stored in msg.txt is output to hmac.bin, and the output value is dumped in hexadecimal. The key value is
Specify the key value with the -k option of the command. For the key value, specify the value given as a character string converted to hexadecimal by the xxd command for easy understanding as an example.

```
$ ./hmac -k `echo -n" TLS1.3 "| xxd -p` msg.txt hmac.bin
$ hexdump hmac.bin
0000000 fa b6 cf a5 49 a1 f7 c3 f4 99 ab fc 9f ae 33 cf
0000010 c9 d4 4b d9
0000014
```
Find the HMAC values ​​for the same file with the OpenSSL dgst subcommand and make sure they are the same.

```
$ more msg.txt | openssl dgst -sha1 -hmac "TLS1.3"
(stdin) = fab6cfa549a1f7c3f499abfc9fae33cfc9d44bd9
```

#### 3) Program


```
void algo_main (...)
{
    EVP_MD_CTX_init (& mdCtx);

    if (EVP_DigestInit (& mdCtx, EVP_sha256 ())! = SSL_SUCCESS) {
        / * Error handling * /
    }

    if ((hctx = HMAC_CTX_new ()) == NULL) {
    {/ * Error handling * /}

    if (HMAC_Init_ex (hctx, key, key_sz, md, NULL)! = SSL_SUCCESS) {
    {/ * Error handling * /}

    while (1) {
        if ((inl = fread (in, 1, BUFF_SIZE, infp)) <0) {
           / * Error handling * /
        }
        if (EVP_DigestUpdate (& mdCtx, in, inl)! = SSL_SUCCESS) {
            / * Error handling * /
        }
        if (inl <BUFF_SIZE)
            break;
    }
 
    if (EVP_DigestFinal (& mdCtx, digest, & dmSz)! = SSL_SUCCESS) {
        / * Error handling * /
    }

    if (fwrite (digest, dmSz, 1, outfp)! = 1) {
        / * Error handling * /
    }
    
    ...
}
```
<br> <br> <br>

| Function | Function name |
| --- | --- |
Securing the context | HMAC_CTX_new |
| Contextual duplication | HMAC_CTX_copy |
| Get MD structure | HMAC_CTX_get_md |
| Initial Settings | HMAC_Init_ex |
Hash update | HMAC_Update |
| Termination | HMAC_Final |
| Context release | HMAC_CTX_free |
<br> <br>

Hash algorithm | Algorithm string |
| --- | --- |
| MD5 | "MD5" |
BLAKE128 | "BLAKE128" |
BLAKE256 | "BLAKE256" |
| SHA1 | "SHA1" |
| SHA224 | "SHA224" |
| SHA256 | "SHA256" |
| SHA384 | "SHA384" |
SHA3_224 | "SHA3_224" |
SHA3_256 | "SHA3_256" |
SHA3_384 | "SHA3_384" |
SHA3_512 | "SHA3_512" |

<br> <br> <br>

## 7.4 Common key cryptography

### 1) Overview

OpenSSL / wolfSSL provides a set of functions starting with "EVP" for processing symmetric key cryptography. This section describes the general rules for this EVP function and an example of a symmetric-key cryptographic program that uses it.

At the beginning of the process, the "CTX_new" function allocates a management block for managing the process context. Next, use the "Init" function to set parameters such as the key and IV for the context secured by the initialization function.

The encryption / decryption process is performed by the "Update" function. Processing is performed on the input buffer in memory and output to the output buffer. If the memory size limit allows, the entire input data can be passed to the "Update" function at once, but if there is a limit, the "Update" function can be called multiple times by dividing it into appropriate sizes. increase. At that time, you can specify an appropriate processing size without worrying about the block size of the block type encryption. Finally, the "Final" function processes the padding for odd data.

Finally, release the management block after the end.


### 2) Commands and usage examples

The following is a sample program that realizes symmetric-key cryptographic processing using the EVP function. Various cipher algorithms and usage modes can be processed by changing the definition of the "CIPHER" constant (see "6) Cipher algorithms and usage modes for the cipher suites that can be specified).

See Examples / 2.Chrypto/sym/aes-cbc.c for working sample code. This program accepts the following command agreements:


- Input file: Uses the file with the specified file name as input data.
- Output file: Outputs the result data to the file with the specified file name. If omitted, output to standard output.

-"-e" specifies encryption, "-d" specifies compound. If not specified, encryption processing will be performed.
- Specify the key value in hexadecimal in the next argument after "-k". The key length is 16 bytes.
- Specify the IV value in hexadecimal in the next argument after "-i". The IV length is 16 bytes.
<br> <br> <br>



The contents of msg.txt are encrypted with AES-128-CBC and output to enc.bin. For the key and IV value, specify the value given as a character string converted to hexadecimal by the xxd command for easy understanding as an example. Decrypt to dec.txt with enc.bin as input. Make sure that the contents are restored with the diff command.

```
$ ./aescbc -i `echo -n" 1234567812345678 "| xxd -p` -k `echo -n" 0123456701234567 "| xxd -p` msg.txt enc.bin
$ ./aescbc -i `echo -n" 1234567812345678 "| xxd -p` -k `echo -n" 0123456701234567 "| xxd -p` -d enc.bin dec.txt
$ diff msg.txt dec.txt
```

If you change the key value and decrypt, the padding cannot be decrypted normally at the end of decryption, so an error will occur in EVP_CipherFinal. The output content is also different from the original one.

```
$ ./aescbc -i `echo -n" 1234567812345678 "| xxd -p` -k `echo -n" 0123456701234568 "| xxd -p` -d enc.bin dec2.txt
ERROR: EVP_CipherFinal
$ diff msg.txt dec2.txt
Binary files msg.txt and dec.txt differ
$ hexdump dec.txt
0000000 43 43 20 3d 20 67 63 63 0a 23 43 43 20 3d 20 63
...

$ hexdump dec2.txt
0000000 47 b6 f8 d1 ff 67 d9 c1 79 00 21 d5 22 ae 6c 8f
...

```

### 3) Program

```
#define CIPHER EVP_aes_128_CBC ()

int algo_main (int mode, FILE * infp, FILE * outfp,
               unsigned char * key, int key_sz,
               unsigned char * iv, int iv_sz,
               unsigned char * tag, int tag_sz)
{
    ...

    Handling command agreements

    if ((evp = EVP_CIPHER_CTX_new ()) == NULL)
    {/ * Error handling * /}

    / * Start cipher process * /
    if (EVP_CipherInit (evp, CIPHER, key, iv, mode)! = SSL_SUCCESS)
    {/ * Error handling * /}

    while (1) {
        if ((inl = fread (in, 1, BUFF_SIZE, infp)) <0)
        {/ * Error handling * /}

        if (EVP_CipherUpdate (evp, out, & outl, in, inl)! = SSL_SUCCESS)
        {/ * Error handling * /}

        fwrite (out, 1, outl, outfp);
        if (inl <BUFF_SIZE)
            break;
    }

    if (EVP_CipherFinal (evp, out, & outl)! = SSL_SUCCESS)
    {/ * Error handling * /}

    EVP_CipherFinal (evp, out, & outl);
    fwrite (out, 1, outl, outfp);
    ret = SSL_SUCCESS;
    / * End cipher process * /

```
<br> <br> <br>

### 3) Authenticated encryption (AEAD)

In the case of authenticated encryption such as AES-GCM, it is necessary to handle the authentication tag. As shown in the program below, when encrypting, get the authentication tag to be used for decryption after "Final". When decrypting, set the tag before "Final". Confirm that the authentication tag verification is successful by confirming that the return value of the "Final" process is successful.
<br> <br> <br>
See Examples / 2.Chrypto/sym/aes-cbc.c for working sample code. This program accepts the following command agreements:


- Input file: Uses the file with the specified file name as input data.
- Output file: Outputs the result data to the file with the specified file name. If omitted, output to standard output.

-"-e" specifies encryption, "-d" specifies compound. If not specified, encryption processing will be performed.
- Specify the key value in hexadecimal in the next argument after "-k".
- Specify the IV value in hexadecimal in the next argument after "-i".
- Specify the tag value in hexadecimal in the next argument after "-t".



The contents of msg.txt are encrypted with AES-128-GCM and output to enc.bin. For the key and IV value, specify the value given as a character string converted to hexadecimal by the xxd command for easy understanding as an example. When you execute the encryption command, the tag value is output in hexadecimal to the standard output.

Then take enc.bin as input and decrypt it to dec.txt. Enter the tag value obtained during encryption with the -t option. Make sure that the contents are restored with the diff command.

```
$ ./aesgcm -i `echo -n" 123456781234 "| xxd -p` -k `echo -n" 0123456701234567 "| xxd -p` msg.txt enc.bin
d25e7835efaf7f8cae6be966535d36d5


$ ./aesgcm -i `echo -n" 123456781234 "| xxd -p` -k `echo -n" 0123456701234567 "| xxd -p` -t d25e7835efaf7f8cae6be966535d36d5 -d enc.bin dec.txt

$ diff msg.txt dec.txt
```

Confirm that the output tag value is different when the key value is changed.


```
$ ./aesgcm -i `echo -n" 123456781234 "| xxd -p` -k `echo -n" 0123456701234568 "| xxd -p` msg.txt enc.bin
76dcb79109643631648765e4413a2d8c
```

```

#define CIPHER EVP_aes_128_gcm ()

int algo_main (int mode, FILE * infp, FILE * outfp,
                 unsigned char * key, int key_sz,
                 unsigned char * iv, int iv_sz,
                 unsigned char * tagIn, int tag_sz)
{

    Command argument check

    if ((evp = EVP_CIPHER_CTX_new ()) == NULL)
    {/ * Error handling * /}

    if (EVP_CipherInit (evp, CIPHER, key, iv, mode)! = SSL_SUCCESS)
    {/ * Error handling * /}
    / * End argment check * /

    / * Start cipher process * /
    while (1) {
        if ((inl = fread (in, 1, BUFF_SIZE, infp)) <0)
        {/ * Error handling * /}
        if (EVP_CipherUpdate (evp, out, & outl, in, inl)! = SSL_SUCCESS)
        {/ * Error handling * /}
        if (fwrite (out, 1, outl, outfp)! = outl)
            goto cleanup;
        if (inl <BUFF_SIZE)
            break;
    }

    if (mode == DEC)
        if (EVP_CIPHER_CTX_ctrl (evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tagIn)! = SSL_SUCCESS)
        {/ * Error handling * /}

    if (EVP_CipherFinal (evp, out, & outl)! = SSL_SUCCESS) / * Padding process * /
        Error handling
    else else
        fwrite (out, 1, outl, outfp);

    if (mode == ENC) {
        if (EVP_CIPHER_CTX_ctrl (evp, EVP_CTRL_AEAD_GET_TAG, tag_sz, tagOut)! = SSL_SUCCESS)
        {/ * Error handling * /}
        for (i = 0; i <tag_sz; i ++)
            printf ("% 02x", tagOut [i]);
        putchar ('\ n');
    }

    if (fwrite (out, 1, outl, outfp)! = outl)
        goto cleanup;
    ret = SSL_SUCCESS;
    / * End cipher process * /

    ...

}


```
### 4) EVP function naming convention

The EVP function provides two series of functions, one for when the direction of symmetric key encryption or decryption is statically determined at programming time, and one for when the direction of symmetric-key encryption or decryption processing is dynamically determined at run time. .. If static, the function name contains the name "Encrypt" or "Decrypt" to indicate the direction of processing. If it is dynamic, the function name will be named "Cipher" and the direction of processing will be specified during the initial setup of EVP_CipherInit. The following table summarizes the function names for these symmetric-key processes.

| Functions | Encryption | Decryption | Dynamic specification |
| --- | --- | --- | --- |
Securing context | EVP_CIPHER_CTX_new | EVP_CIPHER_CTX_new | EVP_CIPHER_CTX_new |
| Initial Settings | EVP_EncryptInit | EVP_DecryptInit | EVP_CipherInit |
| Encryption / Decryption | EVP_EncryptUpdate | EVP_DecryptUpdate | EVP_CipherUpdate |
End processing | EVP_EncryptFinal | EVP_DecryptFinal | EVP_CipherFinal |
Context release | EVP_CIPHER_CTX_free | EVP_CIPHER_CTX_free | EVP_CIPHER_CTX_free |


### 5) Padding process
The EVP function automatically performs padding for block cryptography. The padding scheme is PKCS. Therefore, in the case of encryption processing, it should be noted that the processing result will be larger by the amount aligned to an integral multiple of the block size compared to the size of the input data. Even if the input data is an integral multiple of the block size, one block of output data will be added for padding. On the other hand, when decrypting, the padding content is eliminated and only the original output data that was decrypted is available. The output data size of the encryption / decryption process including padding is returned to the argument of the "Final" function.

The scheme specified in PKCS # 7 is used for the padding scheme (see 3.4 Common Key Cryptography 4) Padding Scheme).

<br> <br> <br>

### 6) Cryptographic algorithm, usage mode

In EVP, processing can be handled in a unified manner by setting processing parameters such as various cryptographic algorithms and usage modes with the "Init" function. Below is a summary of the main cipher suites that can be specified with "Init".

| Symbol | Algorithm | Block length | Key length | Usage mode |
| --- | --- | --- | --- | --- |
EVP_aes_xxx_cbc | AES | 128 | xxx: 128, 192, 256 | CBC |
EVP_aes_xxx_cfb1 | AES | 128 | xxx: 128, 192, 256 | CFB1 |
EVP_aes_xxx_cfb8 | AES | 128 | xxx: 128, 192, 256 | CFB8 |
EVP_aes_xxx_cfb128 | AES | 128 | xxx: 128, 192, 256 | CFB128 |
EVP_aes_xxx_ofb | AES | 128 | xxx: 128, 192, 256 | OFB |
EVP_aes_xxx_xts | AES | 128 | xxx: 128, 256 | XTS |
EVP_aes_xxx_gcm | AES | 128 | xxx: 128, 192, 256 | GCM |
EVP_aes_xxx_ecb | AES | 128 | xxx: 128, 192, 256 | ECB |
EVP_aes_xxx_ctr | AES | 128 | xxx: 128, 192, 256 | CTR |
EVP_des_cbc | DES | 64 | 56 | CBC |
EVP_des_ecb | DES | 64 | 56 | ECB |
EVP_des_ede3_cbc | DES-EDE3 | 64 | 168 | CBC |
EVP_des_ede3_ecb | DES-EDE3 | 64 | 168 | ECB |
EVP_idea_cbc | IDEA | 64 | 128 | CBC |
| EVP_rc4 | RC4 ||||

### 7) Other APIs

<br>
The main EVP functions related to the processing of symmetric-key cryptography are summarized below.
<br>

| Function name | Function |
| --- | --- |
EVP_CIPHER_CTX_iv_length, EVP_CIPHER_iv_length | Get IV size |
EVP_CIPHER_CTX_key_length, EVP_CIPHER_key_length | Get key size |
| EVP_CIPHER_CTX_mode, EVP_CIPHER_mode | Get encryption / decryption mode |
EVP_CIPHER_CTX_block_size, EVP_CIPHER_block_size | Get block size |
EVP_CIPHER_CTX_flags, EVP_CIPHER_flags | Get flags |
EVP_CIPHER_CTX_cipher | Get algorithm |
EVP_CIPHER_CTX_set_key_length | Set key size |
EVP_CIPHER_CTX_set_iv | Set IV size |
EVP_CIPHER_CTX_set_padding | Set padding |
EVP_CIPHER_CTX_set_flags | Set flags |
EVP_CIPHER_CTX_clear_flags | Clear flags |
EVP_CIPHER_CTX_reset | Reset context <br> (backward compatibility: no longer needed with EVP_CIPHER_CTX_FREE) |
EVP_CIPHER_CTX_cleanup | Clean up the context <br> (backward compatibility: no longer needed with EVP_CIPHER_CTX_FREE) |



## 7.5 Public key cryptography
### 7.5.1 RSA key pair generation

#### 1) Overview
This sample program generates a pair of RSA private and public keys. Generate the key in the internal format (RSA structure) with RSA_generate_key. This is converted into a DER format private key and public key with i2d_RSAPrivateKey and i2d_RSAPublicKey, and output to each file.

#### 2) Command format and usage

In the sample program, specify the following arguments.
- First Argument: Private key file name
- Second argument: File name of public key


Start the sample program by specifying the private key (pri.der) and public key file name (pub.der) you want to generate.

```
$ ./genrsa pri.der pub.der
```

Check the contents of the generated private key and public key using the rsa subcommand of the OpenSSL command.

Check the contents of the generated private key and public key using the rsa subcommand of the OpenSSL command.

```
Confirmation of private key
$ openssl rsa -in pri.key -inform DER -text -noout
Private-Key: (2048 bit)
modulus: modulus:
    00: 8c: 32: 87: e1: 0f: 51: e5: 19: 59: 59: c7: a6: ff: 8f:
    ...
    ff: 2a: a1: b4: 65: 61: 01: 9b: 37: ce: 51: bd: b9: 0b: ba:
    46:77
publicExponent: 3 (0x3)
privateExponent:
    5d: 77: 05: 40: b4: e1: 43: 66: 3b: 91: 2f: c4: aa: 5f: 84:
    ...
    76: f9: 91: fc: ec: 75: 6c: 93: 3e: 97: ea: 1a: 67: 5f: 3c:
    bb
prime1: prime1:
    00: c1: db: 4c: 73: 80: e5: a3: 5c: 71: 01: 11: 21: 9f: c2:
    ...
    8b: 07: 53: 1d: 74: 8a: 85: 8b: 73
prime2:
    00: b9: 23: b9: bc: 64: 79: 8d: 83: 7a: ec: 44: 0a: a5: 65:
    ...
    cf: e9: 1a: c1: 1c: e6: 25: df: ed
exponent1: exponent1:
    00: 81: 3c: dd: a2: 55: ee: 6c: e8: 4b: 56: 0b: 6b: bf: d6:
    ...
    5c: af: 8c: be: 4d: b1: ae: 5c: f7
exponent2:
    7b: 6d: 26: 7d: 98: 51: 09: 02: 51: f2: d8: 07: 18: ee: 2e:
    ...
    46: 11: d6: 13: 44: 19: 3f: f3
coefficient:
    00: 80: 30: ba: 36: 30: 56: f8: f2: 54: 48: 4d: b5: c0: ac:
    ...
    1d: f9: 19: 2b: d0: 1d: cc: 37: db


Confirmation of public key
$ openssl rsa -pubin -in pub.key -inform DER -text -noout
Public-Key: (2048 bit)
Modulus:
    00: 8c: 32: 87: e1: 0f: 51: e5: 19: 59: 59: c7: a6: ff: 8f:
    ...
    ff: 2a: a1: b4: 65: 61: 01: 9b: 37: ce: 51: bd: b9: 0b: ba:
    46:77
Exponent: 3 (0x3)
```

#### 3) Program

RSA_generate_key generates an RSA key pair and a pointer to the key pair is returned as the return value. Of the key to generate
The size is specified in the first argument. Stored in this
Buffer the public and private keys into i2d_RSAPrivateKey and i2d_RSAPublicKey in DER format, respectively.
A pointer to the fetched buffer is returned in the second argument. In the sample program, each key is
Output to the specified file.

```
int algo_main (...)
{

    rsa = RSA_generate_key (RSA_SIZE, RSA_E, NULL, NULL);
    if (rsa == NULL) {
        / * Error handling * /
    }
    pri_sz = i2d_RSAPrivateKey (rsa, & pri);
    pub_sz = i2d_RSAPublicKey (rsa, & pub);
    if (pri == NULL || pub == NULL) {
        / * Error handling * /
    }
    
    if (fwrite (pub, 1, pub_sz, fpPub)! = pub_sz) {
        / * Error handling * /
    }

    if (fwrite (pri, 1, pri_sz, fpPri)! = pri_sz) {
        / * Error handling * /
    }
    ...

}
```

#### 4) Main API
<br>
The main functions related to the key generation process are summarized below.

<br>

| Function name | Function |
| --- | --- |
RSA_generate_key | Generate RSA key pair |
| i2d_RSA_PrivateKey | Get RSA private key data in DER format |
| i2d_RSA_PublicKey | Get RSA public key data in DER format |

<br>

### 7.5.2 RSA encryption and decryption

#### 1) Overview
Here, we will introduce an example of an RSA encryption / decryption program. The program is divided into encryption (rsaEnc.c) and decryption (rsaDec.c).

The encryption program reads the message to be encrypted and the public key file, and transforms the public key in DER format into an internal format. Securing the processing context,
Specify the padding scheme in the initialization and execute RSA encryption with EVP_PKEY_encrypt.

At that time, first specify NULL for the second argument (output buffer) of EVP_PKEY_encrypt and check the validity of the message size.
At this time, no encryption process is performed. Next, specify the output buffer pointer and call the EVP_PKEY_encrypt function to actually execute the encryption process.

Finally, the result is output to a file.

The flow of compound processing is the same as cryptographic processing except that the key used is a private key and the EVP_PKEY function calls decrypt.

#### 2) Command format and usage

In the encryption / decryption command, specify the key file and target message file as follows.


- encryption

- First Argument: Public key used for encryption
- Second argument: Encrypted message output file name
- Standard input: Message to be encrypted


- Decryption

- First argument: Private key used for decryption
- Second argument: Decrypted message output file name
- Standard input: Message to be decrypted


In the following example, first store the sample message to be encrypted in msg.txt.

7.5.1 Encrypt this into enc.dat using the public key generated by RSA key pair generation.
Decrypt the data (enc.dat) encrypted with the private key to dec.txt.


```
$ more msg.txt
12345678901234567890
$ ./rsaenc ../04.keyGen/pub.key enc.dat <msg.txt

$ hexdump enc.dat
0000000 5f 98 07 3c 88 2c 6a a7 be 86 89 1e 15 30 d8 82
0000010 37 0b 4e 11 e4 70 e6 41 99 6d c7 3b 6b 24 0d 65
0000020 00 8e ec b3 97 7b 7e e7 9f 1d 00 ca 7d e5 e4 13
0000030 26 37 18 bd 20 83 97 6d a1 f0 38 70 b9 e8 22 78
0000040 dc 04 2d 7c 5f 0e f7 27 9c 01 b5 fa 1a e6 96 13
0000050 96 fb 48 e7 ed 27 8d c9 61 dc 12 83 16 81 f8 79
0000060 4d ea c2 df 6f ab 5c 5c 4c fd 1d e5 59 b0 79 8c
0000070 1f 05 c2 e4 16 70 26 b7 dd df 87 1c 5a 12 59 42
0000080 33 52 1f ad 4d 83 5d a0 10 e1 97 a9 f6 e6 6c 66
0000090 87 48 e4 ea 50 bd d7 45 45 f4 a8 d6 f6 e1 03 6b
00000a0 28 16 03 36 6d 14 6d d7 ca b3 35 a0 4e 72 75 4b
00000b0 7f d1 2e 9a ac 6c 71 b3 55 26 5d 12 94 f3 c4 54
00000c0 93 df 8c 58 d1 f1 94 79 41 62 9a 41 3e 8e b6 0b
00000d0 a9 51 a3 c0 71 7f 5e ce 61 cc 54 c4 61 0f 2a 1f
00000e0 0e 9b 46 87 0f cb 07 63 85 03 ba 1b aa f8 f4 e8
00000f0 79 2e d4 3c 7b 4d e0 2e 5c f4 5a dd 68 c5 69 7f
0000100
MacBook-Pro-3: 05.rsaEnc kojo $ ./rsadec ../04.keyGen / pri.key dec.txt <enc.dat
MacBook-Pro-3: 05.rsaEnc kojo $ more dec.txt
12345678901234567890
MacBook-Pro-3: 05.rsaEnc kojo $ diff msg.txt dec.txt
```

```
$ ./rsadec ../04.keyGen / pri.key dec.txt <enc.dat
$ diff msg.txt dec.txt
$ more dec.txt
12345678901234567890
```

### 3) Program
####  encryption

```
int algo_main (...)
{
    if ((msg_sz = fread (msg, 1, BUFF_SIZE, stdin)) <0) {
        / * Error handling * /}

    if ((key_sz = fread (key_buff, 1, sizeof (key_buff), fpKey)) <0) {
        / * Error handling * /}

    if ((pkey = d2i_PublicKey (EVP_PKEY_RSA, NULL, & p, key_sz)) == NULL) {
        / * Error handling * /}

    if ((ctx = EVP_PKEY_CTX_new (pkey, NULL)) == NULL) {
        / * Error handling * /}

    if (EVP_PKEY_encrypt_init (ctx)! = SSL_SUCCESS) {
        / * Error handling * /}

    if (EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_OAEP_PADDING)! = SSL_SUCCESS) {
        / * Error handling * /}

    if (EVP_PKEY_encrypt (ctx, NULL, & enc_sz, msg, msg_sz)! = SSL_SUCCESS) {
        / * Error handling * /}
    if (ENC_SIZE! = enc_sz) {
        / * Error handling * /}

    if (EVP_PKEY_encrypt (ctx, enc, & enc_sz, msg, msg_sz)! = SSL_SUCCESS) {
        / * Error handling * /}

    if (fwrite (enc, 1, enc_sz, fpEnc)! = enc_sz) {
        / * Error handling * /}

    ...
}
```

#### Decryption

```
int algo_main (...)
{

    if ((msg_sz = fread (msg, 1, BUFF_SIZE, stdin)) <0) {
        / * Error handling * /}

    if ((key_sz = fread (key_buff, 1, sizeof (key_buff), fpKey)) <0) {
        / * Error handling * /}

    if ((pkey = d2i_PrivateKey (EVP_PKEY_RSA, NULL, & p, key_sz)) == NULL) {
        / * Error handling * /}

    if ((ctx = EVP_PKEY_CTX_new (pkey, NULL)) == NULL) {
        / * Error handling * /}

    if (EVP_PKEY_decrypt_init (ctx)! = SSL_SUCCESS) {
        / * Error handling * /}

    if (EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_OAEP_PADDING)! = SSL_SUCCESS) {
        / * Error handling * /}

    if (EVP_PKEY_decrypt (ctx, NULL, & dec_sz, msg, msg_sz)! = SSL_SUCCESS) {
        / * Error handling * /}
    if (DEC_SIZE! = dec_sz) {
        / * Error handling * /}

    if (EVP_PKEY_decrypt (ctx, dec, & dec_sz, (const unsigned char *) msg, msg_sz)! = SSL_SUCCESS) {
        / * Error handling * /}

    if (fwrite (dec, 1, dec_sz, fpDec)! = dec_sz) {
        / * Error handling * /}
    ...

}
```

### 3) Main APIs used
<br>
The main functions related to encryption / combined processing are summarized below.

<br>

| Function name | Function |
| --- | --- |
| d2i_PrivateKey | Generate encryption key structure from DER format data |
| EVP_PKEY_CTX_new | Context generation for encryption / decryption processing |
EVP_PKEY_CTX_set_rsa_padding | Specifying the padding method |
EVP_PKEY_encrypt_init | Initialization of encryption process |
| EVP_PKEY_encrypt | Execution of encryption processing |
EVP_PKEY_decrypt_init | Initialization of decryption process |
EVP_PKEY_decrypt | Execution of decryption process |
| EVP_PKEY_CTX_free | Free context for encryption / decryption processing |
EVP_PKEY_free | Release encryption key structure |


## 7.5.3 RSA Signature / Verification

#### 1) Overview

signature:

At the beginning of processing, the "EVP_MD_CTX_new" function allocates a management block for managing the processing context. Next, use the "EVP_DigestSignInit" function to set parameters such as the key and hash algorithm type for the context secured by the initialization function.

Use the "EVP_DigestSignUpdate" function to get the digest of the target message. If the memory size limit allows, the entire target message can be passed to the "EVP_DigestSignUpdate" function at once, but if there is a limit, the "EVP_DigestSignUpdate" function can be called multiple times by dividing it into appropriate sizes. increase. After reading all the messages, the signature value is calculated from the digest value and signature key obtained by the "EVP_DigestSignFinal" function.

Finally, release the management block after the end.

inspection:

At the beginning of processing, the "EVP_MD_CTX_new" function allocates a management block for managing the processing context. Next, use the "EVP_DigestVerifyInit" function to set parameters such as the key and hash algorithm type for the context secured by the initialization function.

Use the "EVP_DigestVerifyUpdate" function to get a digest of the target message. If the memory size limit allows, the entire target message can be passed to the "EVP_DigestVerifyUpdate" function at once, but if there is a limit, the "EVP_DigestVerifyUpdate" function can be called multiple times by dividing it into appropriate sizes. increase. After reading all the messages, verify the signature value with the "EVP_DigestVerifyFinal" function.

Finally, release the management block after the end.

#### 2) Command format and usage

The following is a sample program for RSA signature and verification using the EVP function. This program accepts the following command agreements:

#### Signature: rsasig

Command Argument: <br>
- Input file: DER format signature key file <br>
- Output file: Outputs the signature value. If omitted, output to standard output. <br>
- Standard input: Enter the message to be signed


#### Verification: rsaver

Command Argument: <br>
- Input file 1: DER format verification key file <br>
- Input file 2: File containing signature value <br>
- Standard input: Enter the message to be signed

<br> <br> <br>

Prepare a sample message in msg.txt. 7.5.1 Generate the signature of the sample data using the private key generated by RSA key pair generation as the signature key. The signature is output to sig.der. Validate the signature with the signature and sample message as input to verify that it is validated correctly.

```
$ ./rsasig ../04.keyGen / pri.key sig.der <msg.txt
$ ./rsaver ../04.keyGen / pub.key sig.der <msg.txt
Signature Verified
```

Next, create a message (msg2.txt) with minor modifications to the sample message, and use it to verify that the tampered message is detected as a bad signature.

```
$ ./rsaver ../04.keyGen / pub.key sig.der <msg2.txt
Invalid Signature Invalid Signature
```

#### Program

```
signature

int algo_main (...)
{
    ...
    / * Read signing key * /
    key_sz = fread (in, 1, size, infp);
    pkey = d2i_PrivateKey (EVP_PKEY_RSA, NULL, & inp, key_sz);

    / * Preparation of management block * /
    md = EVP_MD_CTX_new ();
    EVP_DigestSignInit (md, NULL, HASH, NULL, pkey);

    / * Read message and ask for digest * /
    for (; size> 0; size-= BUFF_SIZE) {
        inl = fread (msg, 1, BUFF_SIZE, stdin);
        EVP_DigestSignUpdate (md, msg, inl);
    }

    / * Signature generation * /
    EVP_DigestSignFinal (md, sig, & sig_sz);
    fwrite (sig, 1, sig_sz, outfp)! = sig_sz);
```

```
    inspection
    / * Read verification key and signature * /
    key_sz = fread (pubkey, 1, KEY_SIZE, infp);
    sig_sz = fread (sig, 1, SIG_SIZE, fp2);
    pkey = d2i_PublicKey (EVP_PKEY_RSA, NULL, & p, key_sz);

    / * Secure and set management block * /
    md = EVP_MD_CTX_new ());
    EVP_DigestVerifyInit (md, NULL, HASH, NULL, pkey)! = SSL_SUCCESS) {
        fprintf (stderr, "EVP_DigestVerifyInit \ n");
        goto cleanup;
    }

    / * Read message and ask for digest * /
    for (; size> 0; size-= BUFF_SIZE) {
        inl = fread (msg, 1, BUFF_SIZE, stdin)) <0);
        EVP_DigestVerifyUpdate (md, msg, inl);

    / * Signature verification * /
    EVP_DigestVerifyFinal (md, sig, sig_sz) == SSL_SUCCESS)
        printf ("Signature Verified \ n");
    else else
        printf ("Invalid Signature \ n");
```


### 3) Main APIs used
<br>
The main functions related to the signature / verification process are summarized below.

<br>

| Function name | Function |
| --- | --- |
| d2i_PrivateKey | Generate signature / verification key structure from DER format data |
| EVP_MD_CTX_new | Context generation for signature processing |
EVP_DigestSignInit | Initialization of signature processing |
EVP_DigestSignUpdate | Signature data update |
EVP_DigestSignFinal | Signature processing finalization |
EVP_DigestVerifyInit | Initialization of signature verification process |
EVP_DigestVerifyUpdate | Signature Verification Data Update |
EVP_DigestVerifyFinal | Finalize signature verification |
EVP_PKEY_free | Signature / Verification Key Release key structure |
EVP_MD_CTX_free | Free message digest structure |

<br>

## 7.8 X509 Certificate

Here, we will introduce the following sample program related to certificates.

―― 1) Creating a CSR
―― 2) Creating a self-signed certificate
- 3) Certificate verification
―― 4) Retrieving certificate items

### 7.8.1 Creating a CSR

    name = X509_NAME_new ();
    509_NAME_add_entry_by_txt (name, "commonName", MBSTRING_UTF8,
                                           (byte *) "wolfssl.com", 11, 0, 1);
    X509_NAME_add_entry_by_txt (name, "emailAddress", MBSTRING_UTF8, (byte *) "support@wolfssl.com", 19, -1, 1);

    d2i_PrivateKey (EVP_PKEY_RSA, NULL, & rsaPriv,
                                        (long) sizeof_client_key_der_2048);
    pub = d2i_PUBKEY (NULL, & rsaPub,
                                   (long) sizeof_client_keypub_der_2048);
    eq = X509_REQ_new ();

    X509_REQ_set_subject_name (req, name);
    X509_REQ_set_pubkey (req, pub);
    X509_REQ_sign (req, priv, EVP_sha256 ());
    i2d_X509_REQ (req, & der), 643);
    XFREE (der, NULL, DYNAMIC_TYPE_OPENSSL);
    der = NULL;

    mctx = EVP_MD_CTX_new ();
    EVP_DigestSignInit (mctx, & pkctx, EVP_sha256 (), NULL, priv);
    X509_REQ_sign_ctx (req, mctx);

    EVP_MD_CTX_free (mctx);
    X509_REQ_free (NULL);
    X509_REQ_free (req);
    EVP_PKEY_free (pub);
    EVP_PKEY_free (priv);

### 2) Verification

    bio = BIO_new_file (csrFile, "rb");
    d2i_X509_REQ_bio (bio, & req);
    pub_key = X509_REQ_get_pubkey (req);
    X509_REQ_verify (req, pub_key);

    X509_free (req);
    BIO_free (bio);
    EVP_PKEY_free (pub_key);

### 3) Main APIs used
<br>
The main functions related to certificate request processing are summarized below.

<br>

| Function name | Function |
| --- | --- |
| X509_NAME_new | Secure Name Object for Certificates |
| X509_NAME_add_entry_by_txt | Add entry to name object |
| d2i_PrivateKey | Generate key structure from DER format data |
| d2i_PUBKEY | Extract public key |
| X509_REQ_new | Certificate Request Object Generation |
| X509_REQ_set_subject_name | Add subject name to certificate request object |
| X509_REQ_set_pubkey | Set public key in certificate request object |
| X509_REQ_sign | Signing a Certificate Signing Request |
| i2d_X509_REQ | Convert certificate request to DER format |
EVP_MD_CTX_new | Message digest context generation |
EVP_DigestSignInit | Message Digest Initialization |
| X509_REQ_sign_ctx | Sign certificate request using message digest context |
| X509_REQ_free | Certificate Request Object Release |
EVP_PKEY_free | Release encryption key structure |
EVP_MD_CTX_free | Free message digest structure |


The X509 certificate object supports public key certificates, CSR, and CRL objects, and each object supports a function for each function with a function naming convention like a table.


| Features | X509 Certificates | CSR | CRL |
| --- | --- | --- | --- |
| Object name | X509 | X509_REQ | X509_CRL |
| Object Creation | X509_new | X509_REQ_new | X509_CRL_New |
Object release | X509_free | X509_REQ_free | X509_CRL_free |
| Item settings | X509_set_xxx | X509_REQ_set_xxx | X509_CRL_set_xxx |
| Signature | X509_sign | X509_REQ_sign | X509_CRL_sign |
| Input from DER | d2i_X509 | d2i_X509_REQ | d2i_X509_CRL |
Output to DER | id2_X509 | id2_X509_REQ | i2d_X509_CRL |
| Input from PEM | PEM_read_X509 | PEM_read_X509_REQ | PEM_read_X509_CRL |
| Output to PEM | PEM_write_X509 | PEM_write_X509_REQ | PEM_write_X509_CRL |
| Input from PEM | PEM_read_bio_X509 | PEM_read_bio_X509_REQ | PEM_read_bio_X509_CRL |
| Output to PEM | PEM_write_bio_X509 | PEM_write_bio_X509_REQ | PEM_write__bioX509_CRL |

## 7.8.2 Creating a self-signed certificate

### 1) Overview

This sample program creates a self-signed certificate.
Reads the specified public key and private key prepared in advance. Next, create an X509 object and add information such as the public key, random number generated serial number, principal name, and signer name to it. Finally, sign with a private key and output in PEM format.

#### 2) Command format and usage

Command Argument: <br>
- Argument 1: DER format public key <br>
- Argument 2: DER format private key <br>
- Standard output: PEM format self-signed certificate

Example of use:

    Generate a self-signed certificate by specifying the public and private keys generated in the RSA key generation example.
```
$ ./selfsig ../04.keyGen / pub.key ../04.keyGen / pri.key> selfsig.pem
$ openssl x509 -in selfsig.pem -text
Certificate: Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            45: 82: ac: e9: e0: ff: a2: 77: 16: 1c: a6: 86: 7b: e9: fd: 8c
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = www.wolfssl.com
        Validity
            Not Before: Dec 27 05:08:59 2021 GMT
            Not After: Dec 27 05:08:59 2022 GMT
        Subject: CN = www.wolfssl.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00: 8c: 32: 87: e1: 0f: 51: e5: 19: 59: 59: c7: a6: ff: 8f:
                    ...
                    ff: 2a: a1: b4: 65: 61: 01: 9b: 37: ce: 51: bd: b9: 0b: ba:
                    46:77
                Exponent: 3 (0x3)
    Signature Algorithm: sha256WithRSAEncryption
         16: b9: 1f: 5c: 2b: f9: 87: 75: 53: 7d: 1b: de: 82: 39: c8: bc: 9e: 1f:
            ...
         ec: a9: 67: eb: 52: 3e: 8c: da: a7: 80: 97: 20: a6: 26: 75: 9f: 36: 36:
         cd: 23: aa: 2d
----- BEGIN CERTIFICATE -----
MIICujCCAaKgAwIBAgIQRYKs6eD / oncWHKaGe + n9jDANBgkqhkiG9w0BAQsFADAa
...
e1Q1ozrvchWsCQhWGMH7Rx6 / RF / yecwLlEHt08FZDbthEKK4dXtLCt6UGUzlHws4
NlRHDVBU0jjsqWfrUj6M2qeAlyCmJnWfNjbNI6ot
----- END CERTIFICATE -----
```

### 3) Program

```
int algo_main (...)
{
    / * Reading private and public keys * /
    if ((sz = fread (key_buff, 1, sizeof (key_buff), fpPub)) <0)
    {Error handling}

    if ((pubkey = d2i_PublicKey (EVP_PKEY_RSA, NULL, & key_p, sz)) == NULL)
    {Error handling}

   if ((sz = fread (key_buff, 1, sizeof (key_buff), fpPri)) <0)
    {Error handling}

    key_p = key_buff;
    if ((prikey = d2i_PrivateKey (EVP_PKEY_RSA, NULL, & key_p, sz)) == NULL)
    {Error handling}


    / * Create certificate template * /
    if ((x509 = X509_new ()) == NULL)
    {Error handling}

    if (X509_set_pubkey (x509, pkey)! = SSL_SUCCESS)
    {Error handling}

    if ((serial_number = BN_new ()) == NULL)
    {Error handling}

    if (BN_pseudo_rand (serial_number, 64, 0, 0)! = SSL_SUCCESS)
    {Error handling}

    if ((asn1_serial_number = X509_get_serialNumber (x509)) == NULL)
    {Error handling}

    BN_to_ASN1_INTEGER (serial_number, asn1_serial_number);

    / * version 3 * /
    if (X509_set_version (x509, 2L)! = SSL_SUCCESS)
    {Error handling}

    if ((name = X509_NAME_new ()) == NULL)
    {Error handling}

    if (X509_NAME_add_entry_by_NID (name, NID_commonName, MBSTRING_UTF8,
        (unsigned char *) "www.wolfssl.com", -1, -1, 0)! = SSL_SUCCESS)
    {Error handling}

    if (X509_set_subject_name (x509, name)! = SSL_SUCCESS)
    {Error handling}

    if (X509_set_issuer_name (x509, name)! = SSL_SUCCESS)
    {Error handling}

    not_before = (long) time (NULL);
    not_after = not_before + (365 * 24 * 60 * 60);
    X509_time_adj (X509_get_notBefore (x509), not_before, & epoch_off);
    X509_time_adj (X509_get_notAfter (x509), not_after, & epoch_off);

    / * Sign the template * /
    X509_sign (x509, prikey, EVP_sha256 ());

    / * Output in PEM format * /
    if ((sz = PEM_write_X509 (stdout, x509)) == 0)
    {Error handling}

}
```

### 4) Main API

| Function name | Function |
| --- | --- |
| X509_new ||
| X509_free ||
| X509_set_pubkey ||
| BN_new ||
| BN_pseudo_rand ||
| X509_get_serialNumber ||
| BN_to_ASN1_INTEGER ||
| X509_set_version ||
| X509_NAME_new ||
| X509_NAME_add_entry_by_NID ||
| X509_set_subject_name ||
| X509_set_issuer_name ||
| X509_get_notBefore ||
| X509_get_notAfter ||
| X509_time_adj ||
| X509_sign ||
| PEM_write_X509 ||


## 7.8.3 Certificate validation

### 1) Overview

This sample program verifies the signature of the X.509 certificate with the CA certificate.
Read the certificate to be verified for signature and the trusted CA certificate. Next, take out the public key of the CA certificate, verify the target certificate, and display the result.

#### 2) Command format and usage

Command Argument: <br>
- Argument 1: Trusted CA Certificate <br>
- Argument 2: Certificate to be verified <br>
- Standard output:
    Valid certificate: "Verified"
    Illegal certificate: "Failed"


Example of use:

1) Try to verify the server certificate with the CA certificate used in the client and server sample programs.

```
$ ./verifyCert ../../certs/tb-server-cert.pem ../../certs/tb-ca-cert.pem
Verified
```

2) Next, copy the server certificate to the local directory and try to make some corrections.

```
$ cp ../../certs/tb-server-cert.pem ./tb-server-cert2.pem
```

3) After modifying ./tb-server-cert2.pem, regenerate the text images of both certificates and make sure there are differences
confirm.

```
$ openssl x509 -in ../../certs/tb-server-cert.pem -text> ./tb-server-cert.txt
$ openssl x509 -in ./tb-server-cert2.pem -text> ./tb-server-cert2.txt
$ diff ./tb-server-cert.txt ./tb-server-cert2.txt
45c45
<74: 62: d8: 6d: 21: 11: eb: 0c: 82: 50: 22: a0: c3: 88: 52: 7c: b3: c4:
---
> 74: 62: d8: 6d: 21: 11: eb: 0c: 82: 50: 22: a4: c3: 88: 52: 7c: b3: c4:
69c69
<oMOIUnyzxOk4dRH + SkcmN8pW17Wp2WbS45BiHjVtgrAALMTv2dJpk8mQUjYQTTyF
---
> pMOIUnyzxOk4dRH + SkcmN8pW17Wp2WbS45BiHjVtgrAALMTv2dJpk8mQUjYQTTyF
```

4) Validate the modified server certificate.

```
$ ./verifycert ../../certs/tb-ca-cert.pem ./tb-server-cert2.pem
Failed
```


### 3) Program

```
int algo_main (...)
{
    if ((certSv = PEM_read_X509 (fpSv, 0, 0, 0)) == NULL)
    {Error handling}

    if ((certCA = PEM_read_X509 (fpCA, 0, 0, 0)) == NULL)
    {Error handling}

    if ((pkey = X509_get_pubkey (certCA)) == NULL)
    {Error handling}

    if (X509_verify (certSv, pkey) == SSL_SUCCESS)
        printf ("Verified \ n");
    } else {
        printf ("Failed \ n");
    }
```

### Main API

| Function name | Function |
| --- | --- |
| X509_load_certificate_file ||
| X509_get_subject_name ||
| X509_NAME_get_index_by_NID ||
| X509_NAME_get_entry ||
| X509_NAME_ENTRY_get_data ||
| ASN1_STRING_data ||


### Reference

You can specify an X.509 certificate entry to get a pointer to the entry. The main APIs are summarized in the table.

| Function name | Item name |
| --- | --- |
| X509_get_serialNumber ||
| X509_get_subject_name ||
| X509_get_issuer_name ||
| X509_get_notAfter ||
| X509_get_notBefore ||
| X509_get_pubkey ||
| X509_get_version ||