# 7. 暗号アルゴリズム

本章では、各種の暗号アルゴリズムについてサンプルプログラムを紹介します。

## 7.1　共通ラッパー
この章のプログラムはコマンドとして動作するように、共通のラッパーとして動作するmain関数を用意しています。common/main.cにその内容が格納されています。main.cのmain関数は一連のアーギュメントのチェックと解析を行いalgo_main関数を呼び出します。
algo_main関数はアルゴリズムサンプルごとの個別の関数です。このラッパーを使用することにより、個別のアルゴリズムの関数は、アルゴリズムのための固有の処理だけを行うことができます。

このラッパー関数を使ったコマンドは以下のアーギュメントを受け付けます。

- 第1アーギュメント：ファイル名(デフォルト入力、省略可)
- 第2アーギュメント：ファイル名(デフォルト出力、省略可)

以下のオプションアーギュメント：
- -e : 暗号化処理
- -d : 復号処理
- -k : 次のアーギュメントで１６進の鍵値を指定
- -i : 次のアーギュメントで１６進のIV値を指定
- -t : 次のアーギュメントで１６進のタグ値を指定

algo_main関数は、main.h内で以下のように定義されています。main.c内のmain関数はアーギュメントの解析内容をalgo_main関数のアーギュメントに引き継ぎます。

```
void algo_main(int mode, FILE *fp1, FILE *fp2,
                 unsigned char *key, int key_sz, 
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz
                );
```

第一、第2アーギュメントで指定されたファイルはfopenしてファイルディスクリプターfp1, fp2に引き継ぎます。デフォルトのオープンモードはfp1は"rb", fp2は"wb"です。変更する場合はMakefile内でコンパイル時定義のマクロ名 OPEN_MODE1, OPEN_MODE2で任意のモード文字列を定義します。

オープンに失敗した場合はmain.c内でエラーメッセージを出力し、algo_mainは呼び出しません。
アーギュメントが省略された場合はfp1, fp2にはNULLが引き渡されます。


ラッパーとしては -e, -d で示されたモード、-k, -i, -tで指定された任意の長さの１６進値をalgo_mainに引き渡します。不正な16進文字列を検出した場合はmain関数内でエラーを出力し、algo_mainは呼び出しません。指定されていないオプションアーギュメントはポインタ値にNULLが引き渡されます。オプションアーギュメントの必要性、サイズが適切かどうかは個々のalgo_mainにてチェックします。

### バッファーサイズ
サンプルで使用している暗号処理APIはメモリーサイズの許す限り大きなバッファーで一度に処理することができますが、小さな処理単位を繰り返して大きなサイズのデータを処理する例を示すためにあえてバッファーサイズを制限しています。各アルゴリズムのソースコードの先頭付近にある「#define BUFF_SIZE」の定義は適当に変更することができます。


## 7.2 ハッシュ

#### 1) 概要
このサンプルプログラムでは与えられた任意長のメッセージに対するハッシュ値を求めるます。プログラムでは例としてSHA256のハッシュ値を求めます。

#### 2) コマンドと使用例

msg.txtに格納されたメッセージのハッシュ値(バイナリー値)hash.binに出力し、出力された値を１６進ダンプします。

```
$ ./sha256 msg.txt hash.bin
$ hexdump !$
hexdump hash.bin
0000000 c4 e8 fe 54 5d 7c fd b0 07 aa 51 0e 6b 98 d7 7d
0000010 c2 3f e0 f6 75 0f a8 42 08 92 ea 41 96 f5 03 24
0000020
```

同じファイルのハッシュ値をOpenSSL のdgstサブコマンドで求め、同じ値であることを確認します。

```
$ openssl dgst -sha256 msg.txt
SHA256(msg.txt)= c4e8fe545d7cfdb007aa510e6b98d77dc23fe0f6750fa8420892ea4196f50324
```

#### 3) プログラム


プログラムは引数を最大2つ取ります。第1引数は入力データを格納した入力データファイルパスを与えます。第2引数はハッシュデータを出力する先のファイルパスです。第2引数はオプションであり、指定されない場合はハッシュデータは標準出力に出力します。与える入力データのサイズは任意です。出力されるハッシュデータはSHA256の場合は32バイトのバイナリデータとして出力します。

OpenSSL/wolfSSLでは、与えられたデータをハッシュ(メッセージダイジェスト)を求めるための"EVP_MD_CTX", "EVP_Digest"で始まる一連の関数を用意しています。実行するハッシュアルゴリズムはEVP_DigestInit関数で初期化する際に指定します。

処理の始めに処理コンテクストの管理ブロックを用意します(EVP_MD_CTX_init)。次に"EVP_DigestInit"関数により用意したコンテクストに対してハッシュアルゴリズムを指定します。この例ではSHA256を指定します。下記の表に従ってこの部分を変更することで、他のハッシュ
アルゴリズムの処理を行うことができます。

ハッシュ処理は"EVP_DigestUpdate"関数によって行います。メモリーサイズの制限が許す場合は入力データ全体を一括して"EVP_DigestUpdate"関数に渡すことができますが、制限がある場合は適当な大きさに区切って"EVP_DigestUpdate"関数を
複数回呼び出すこともできます。

最後に"EVP_DigestFinal"関数によりコンテクストに保存されていたハッシュ値をバッファーに出力させ、その後ファイル、
あるいは標準出力に出力して終了します。
<br>

|関数名|機能|
|---|---|
|EVP_MD_CTX_new|ハッシュ処理コンテクストを確保|
|EVP_MD_CTX_free|ハッシュ処理コンテクストを解放|
|EVP_DigestInit|ハッシュ種別を指定してコンテクストを初期化|
|EVP_DigestUpdate|対象メッセージを追加。繰り返して呼び出し可能|
|EVP_DigestFinal|ハッシュ値を求める|

表：ハッシュ処理のための基本的な関数


EVP_DigestInitで指定できる主なアルゴリズムを下の表にまとめます。

|アルゴリズム|初期化関数名|
|---|---|
|MD5|EVP_md5|
|Sha1|EVP_sha1|
|Sha224|EVP_sha224|
|Sha256|EVP_sha256|
|Sha384|EVP_sha384|
|Sha512|EVP_sha512|
|Sha512/224|EVP_sha512_224|
|Sha512/256|EVP_sha512_256|
|Sha3/224|EVP_sha3_224|
|Sha3/256|EVP_sha3_256|
|Sha3/284|EVP_sha3_384|
|Sha3/512|EVP_sha3_512|

表：EVP_DigestInitで指定できる主なハッシュアルゴリズム
<br>

# 7.3 メッセージ認証コード

### 1) 概要

OpenSSL/wolfSSLでは、与えられたデータを鍵と共にメッセージ認証コードを生成するための"HAC"で始まる次の様な一連の関数を用意しています。このセクションでは、このHMAC関数を使用したプログラム例について解説します。

このサンプルプログラムでは与えられた任意長のメッセージに対するHMAC値を求めます。
メッセージ認証コードの生成は、入力データと鍵データを合成したうえで指定したハッシュアルゴリズムを使ってハッシュすることで行います。処理の始めに
ハッシュアルゴリズムを選択してメッセージダイジェスト構造体を取得しておきます。その後、処理コンテクストとして管理ブロック"HMAC_CTX"を確保します。次に"Init"関数により初期設定関数で確保したコンテクストに対してメッセージダイジェスト構造体、ハッシュ対象のデータと合成する鍵データを与えて初期化を実行します。

ハッシュ処理は"HMAC_Update"関数によって行います。メモリーサイズの制限が許す場合は入力データ全体を一括して"Update"関数に渡すことができますが、制限がある場合は適当な大きさに区切って"Update"関数を複数回呼び出すこともできます。最後に"Final"関数によりコンテクストに保存されていたハッシュ値(メッセージ認証コード)をバッファーに出力し、ファイルに書き出します。

このプログラムではハッシュアルゴリズムは"SHA1"を使用しています。ハッシュアルゴリズムが設定されたメッセージダイジェスト構造体(EVP_MD)をHMAC初期化関数に渡すことでハッシュアルゴリズムを指定できます。メッセージダイジェスト構造体の取得はEVP_get_digestbyname関数にアルゴリズムを示す文字列を指定することで行います。下表にEVP_get_digestbyname関数に指定できるハッシュアルゴリズム文字列の例を示します。

#### 2) コマンドと使用例

このプログラムでは次のコマンドアーギュメントを受け付けます。

- 入力ファイル：指定されたファイル名のファイルを入力データとして使用します。
- 出力ファイル：指定されたファイル名のファイルに結果のデータを出力します。省略した場合、標準出力に出力します。
- "-k" の次のアーギュメントで鍵値を１６進数で指定します。最低でも1バイトの指定が必要です。

このプログラムで使用するハッシュアルゴリズムは"SHA1"を使用しています。ハッシュアルゴリズムが設定されたメッセージダイジェスト構造体(EVP_MD)を後述のHMAC初期化関数に渡すことでハッシュアルゴリズムを指定できます。

msg.txtに格納されたメッセージのハッシュ値(バイナリー値)hmac.binに出力し、出力された値を１６進ダンプします。鍵値は
コマンドの-kオプションで鍵値を指定します。鍵値は例としてわかりやすいように文字列で与えた値をxxdコマンドで１６進に変換したものを指定します。

```
$ ./hmac -k `echo -n "TLS1.3" |xxd -p` msg.txt hmac.bin
$ hexdump hmac.bin
0000000 fa b6 cf a5 49 a1 f7 c3 f4 99 ab fc 9f ae 33 cf
0000010 c9 d4 4b d9   
0000014                                 
```

同じファイルのHMAC値をOpenSSL のdgstサブコマンドで求め、同じ値であることを確認します。

```
$ more msg.txt | openssl dgst -sha1  -hmac "TLS1.3"
(stdin)= fab6cfa549a1f7c3f499abfc9fae33cfc9d44bd9
```

#### 3) プログラム


```
void algo_main( ... )
{
    EVP_MD_CTX_init(&mdCtx);

    if (EVP_DigestInit(&mdCtx, EVP_sha256()) != SSL_SUCCESS) {
        /* エラー処理 */
    }

    if ((hctx = HMAC_CTX_new()) == NULL) {
    {    /* エラー処理 */ }

    if (HMAC_Init_ex(hctx, key, key_sz, md, NULL) != SSL_SUCCESS) {
    {    /* エラー処理 */ }

    while (1) {
        if ((inl = fread(in, 1, BUFF_SIZE, infp)) <0) {
           /* エラー処理 */
        }
        if (EVP_DigestUpdate(&mdCtx, in, inl) != SSL_SUCCESS) {
            /* エラー処理 */
        }
        if(inl < BUFF_SIZE)
            break;      
    }
 
    if (EVP_DigestFinal(&mdCtx, digest, &dmSz) != SSL_SUCCESS) {
        /* エラー処理 */
    }

    if (fwrite(digest, dmSz, 1, outfp) != 1) {
        /* エラー処理 */
    }
    
    ...
}
```
<br><br><br>

|機能|関数名|
|---|---|
|コンテクスト確保|HMAC_CTX_new|
|コンテクスト複製|HMAC_CTX_copy|
|MD構造体の取得|HMAC_CTX_get_md|
|初期設定|HMAC_Init_ex|
|ハッシュ更新|HMAC_Update|
|終了処理|HMAC_Final|
|コンテクスト解放|HMAC_CTX_free|
<br><br>

|ハッシュアルゴリズム|アルゴリズム文字列|
|---|---|
|MD5|"MD5"|
|BLAKE128|"BLAKE128"|
|BLAKE256|"BLAKE256"|
|SHA1|"SHA1"|
|SHA224|"SHA224"|
|SHA256|"SHA256"|
|SHA384|"SHA384"|
|SHA3_224|"SHA3_224"|
|SHA3_256|"SHA3_256"|
|SHA3_384|"SHA3_384"|
|SHA3_512|"SHA3_512"|

<br><br><br>

## 7.4 共通鍵暗号

### 1) 概要

OpenSSL/wolfSSLでは、共通鍵暗号の処理のために"EVP"で始まる一連の関数が用意されています。このセクションでは、このEVP関数の一般規則とそれを使用した共通鍵暗号のプログラム例について解説します。

処理の始めに"CTX_new"関数により処理コンテクストを管理するための管理ブロックを確保します。次に"Init"関数により初期設定関数で確保したコンテクストに対して鍵、IVなどのパラメータを設定します。

暗号化復号処理は"Update"関数によって行います。メモリー上の入力バッファーに対して処理が行われ、出力バッファーに出力されます。メモリーサイズの制限が許す場合は入力データ全体を一括して"Update"関数に渡すことができますが、制限がある場合は適当な大きさに区切って"Update"関数を複数回呼び出すこともできます。その際ブロック型暗号のブロックサイズを気にすることなく、適当な処理サイズを指定することができます。最後に"Final"関数により半端なデータに対するパディングを処理を行います。

最後に終了後管理ブロックを解放します。


### 2) コマンドと使用例

以下にEVP関数を使用して共通鍵暗号処理を実現するサンプルプログラムを示します。"CIPHER" 定数の定義を変更することで各種の暗号アルゴリズム、利用モードを処理することができます（指定できる暗号スイートについては"6) 暗号アルゴリズム、利用モード"を参照）。

動作可能なサンプルコードはExamples/2.Chrypto/sym/aes-cbc.c を参照してください。このプログラムでは次のコマンドアーギュメントを受け付けます。


- 入力ファイル：指定されたファイル名のファイルを入力データとして使用します。
- 出力ファイル：指定されたファイル名のファイルに結果のデータを出力します。省略した場合、標準出力に出力します。

- "-e"は暗号化、"-d"は複合を指定します。指定のない場合は暗号化処理をします。
- "-k" の次のアーギュメントで鍵値を１６進数で指定します。鍵長は16バイトです。
- "-i" の次のアーギュメントでIV値を１６進数で指定します。IV長は16バイトです。
<br><br><br>



msg.txtの内容をAES-128-CBCで暗号してenc.binに出力します。鍵、IV値は例としてわかりやすいように文字列で与えた値をxxdコマンドで１６進に変換したものを指定します。enc.binを入力としてdec.txtに復号します。diffコマンドで内容が元に戻っていることを確認します。

```
$ ./aescbc -i `echo -n "1234567812345678" |xxd -p` -k `echo -n "0123456701234567" |xxd -p`  msg.txt enc.bin
$ ./aescbc -i `echo -n "1234567812345678" |xxd -p` -k `echo -n "0123456701234567" |xxd -p` -d  enc.bin dec.txt
$ diff msg.txt dec.txt
```

鍵値を変えて復号すると、復号の最後にパディングが正常に復号できないのでEVP_CipherFinalでエラーとなります。出力内容も元のものとは異なります。

```
$ ./aescbc -i `echo -n "1234567812345678" |xxd -p` -k `echo -n "0123456701234568" |xxd -p` -d  enc.bin dec2.txt
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

### 3) プログラム

```
#define CIPHER EVP_aes_128_CBC()

int algo_main(int mode, FILE *infp, FILE *outfp,
               unsigned char *key, int key_sz,
               unsigned char *iv, int iv_sz,
               unsigned char *tag, int tag_sz)
{
    ...

    コマンドアーギュメントの処理

    if ((evp = EVP_CIPHER_CTX_new()) == NULL)
    {    /* エラー処理 */ }

    /* Start cipher process */
    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS)
    {    /* エラー処理 */ }

    while(1) {
        if((inl = fread(in, 1, BUFF_SIZE, infp)) <0)
        {    /* エラー処理 */ }

        if (EVP_CipherUpdate(evp, out, &outl, in, inl) != SSL_SUCCESS)
        {    /* エラー処理 */ }

        fwrite(out, 1, outl, outfp);
        if (inl < BUFF_SIZE)
            break;
    }

    if(EVP_CipherFinal(evp, out, &outl)  != SSL_SUCCESS)
    {    /* エラー処理 */ }

    EVP_CipherFinal(evp, out, &outl);
    fwrite(out, 1, outl, outfp);
    ret = SSL_SUCCESS;
    /* End cipher process */

```         
<br><br><br>

### 3) 認証付き暗号(AEAD)

AES-GCMなど認証付き暗号の場合は認証タグを取り扱う必要があります。下のプログラムで示すように、暗号化の際は、"Final"のあとに復号の際に使用する認証タグを得ておきます。復号の際は、"Final"の前にそのタグを設定します。"Final"処理の返却値が成功であることで認証タグの検証が成功したことを確認します。
<br><br><br>
動作可能なサンプルコードはExamples/2.Chrypto/sym/aes-cbc.c を参照してください。このプログラムでは次のコマンドアーギュメントを受け付けます。


- 入力ファイル：指定されたファイル名のファイルを入力データとして使用します。
- 出力ファイル：指定されたファイル名のファイルに結果のデータを出力します。省略した場合、標準出力に出力します。

- "-e"は暗号化、"-d"は複合を指定します。指定のない場合は暗号化処理をします。
- "-k" の次のアーギュメントで鍵値を１６進数で指定します。
- "-i" の次のアーギュメントでIV値を１６進数で指定します。
- "-t" の次のアーギュメントでタグ値を１６進数で指定します。



msg.txtの内容をAES-128-GCMで暗号してenc.binに出力します。鍵、IV値は例としてわかりやすいように文字列で与えた値をxxdコマンドで１６進に変換したものを指定します。暗号化のコマンドを実行すると標準出力にタグ値が16進で出力されます。

次にenc.binを入力としてdec.txtに復号します。-t オプションで暗号化時に得たタグ値を入力します。diffコマンドで内容が元に戻っていることを確認します。

```
$ ./aesgcm -i `echo -n "123456781234" |xxd -p` -k `echo -n "0123456701234567" |xxd -p`   msg.txt enc.bin
d25e7835efaf7f8cae6be966535d36d5


$ ./aesgcm -i `echo -n "123456781234" |xxd -p` -k `echo -n "0123456701234567" |xxd -p` -t d25e7835efaf7f8cae6be966535d36d5 -d enc.bin dec.txt

$ diff msg.txt dec.txt
```

鍵値を変更すると出力されるタグ値が異なることを確認します。


```
$ ./aesgcm -i `echo -n "123456781234" |xxd -p` -k `echo -n "0123456701234568" |xxd -p`   msg.txt enc.bin
76dcb79109643631648765e4413a2d8c
```

```

#define CIPHER EVP_aes_128_gcm()

int algo_main(int mode, FILE *infp, FILE *outfp,
                 unsigned char *key, int key_sz,
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tagIn, int tag_sz)
{

    コマンドアーギュメントチェック

    if((evp = EVP_CIPHER_CTX_new()) == NULL)
    {    /* エラー処理 */ }

    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS)
    {    /* エラー処理 */ }
    /* End argment check */

    /* Start cipher process */
    while(1) {
        if((inl = fread(in, 1, BUFF_SIZE, infp)) <0)
        {    /* エラー処理 */ }
        if (EVP_CipherUpdate(evp, out, &outl, in, inl) != SSL_SUCCESS)
        {    /* エラー処理 */ }
        if(fwrite(out, 1, outl, outfp) != outl)
            goto cleanup;
        if (inl < BUFF_SIZE)
            break;
    }

    if (mode == DEC)
        if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tagIn) != SSL_SUCCESS)
        {    /* エラー処理 */ }

    if(EVP_CipherFinal(evp, out, &outl) != SSL_SUCCESS) /* パディング処理 */
        エラー処理
    else
        fwrite(out, 1, outl, outfp);

    if (mode == ENC) {
        if(EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_GET_TAG, tag_sz, tagOut) != SSL_SUCCESS)
        {    /* エラー処理 */ }
        for (i = 0; i < tag_sz; i++)
            printf("%02x", tagOut[i]);
        putchar('\n');
    }

    if(fwrite(out, 1, outl, outfp) != outl)
        goto cleanup;
    ret = SSL_SUCCESS;
    /* End cipher process */

    ...

}


```
### 4) EVP関数の命名規則

EVP関数では、共通鍵の暗号または復号処理の方向がプログラミング時に静的に決定している場合のための関数と実行時に動的に決めることができる関数の2つの系列の関数が用意されています。静的な場合は関数名に"Encrypt"または"Decrypt"の命名が含まれていて、処理の方向を表します。動的な場合は関数名には"Cipher"の命名がされ、EVP_CipherInitの初期設定時に処理の方向を指定します。次の表に、これらの共通鍵処理のための関数名をまとめます。

|機能|暗号化|復号|動的指定|
|---|---|---|---|
|コンテクスト確保|EVP_CIPHER_CTX_new|EVP_CIPHER_CTX_new|EVP_CIPHER_CTX_new|
|初期設定|EVP_EncryptInit|EVP_DecryptInit|EVP_CipherInit|
|暗号/復号|EVP_EncryptUpdate|EVP_DecryptUpdate|EVP_CipherUpdate|
|終了処理|EVP_EncryptFinal|EVP_DecryptFinal|EVP_CipherFinal|
|コンテクスト解放|EVP_CIPHER_CTX_free|EVP_CIPHER_CTX_free|EVP_CIPHER_CTX_free|


### 5) パディング処理
EVP関数では、ブロック型暗号のためのパディング処理を自動的に行います。パディングスキームはPKCSです。このため、暗号化処理の場合は処理結果は入力データのサイズに比べてブロックサイズの整数倍にアラインされる分だけ大きくなる点に注意が必要です。入力データがブロックサイズの整数倍の場合にもパディング用に1ブロック分の出力データが付加されます。一方、復号の際はパディングの内容が解消され、復号された本来の出力データのみとなります。パディングを含んだ暗号、復号処理の出力データサイズは"Final"関数のアーギュメントに返却されます。

パディングスキームにはPKCS#7に規定されるスキームが使用されます　(3.4 共通鍵暗号 4)パディングスキーム参照)。

<br><br><br>

### 6) 暗号アルゴリズム、利用モード

EVPでは各種の暗号アルゴリズム、利用モードなどの処理パラメータの設定を"Init"関数で行うことで、処理を統一的に取り扱うことができます。以下に"Init"にて指定できる主な暗号スイートをまとめます。

|シンボル|アルゴリズム|ブロック長|鍵長|利用モード|
|---|---|---|---|---|
|EVP_aes_xxx_cbc   |AES|128|xxx: 128, 192, 256|CBC|
|EVP_aes_xxx_cfb1  |AES|128|xxx: 128, 192, 256|CFB1|
|EVP_aes_xxx_cfb8  |AES|128|xxx: 128, 192, 256|CFB8|
|EVP_aes_xxx_cfb128|AES|128|xxx: 128, 192, 256|CFB128|
|EVP_aes_xxx_ofb   |AES|128|xxx: 128, 192, 256|OFB|
|EVP_aes_xxx_xts   |AES|128|xxx: 128, 256|XTS|
|EVP_aes_xxx_gcm   |AES|128|xxx: 128, 192, 256|GCM|
|EVP_aes_xxx_ecb   |AES|128|xxx: 128, 192, 256|ECB|
|EVP_aes_xxx_ctr   |AES|128|xxx: 128, 192, 256|CTR|
|EVP_des_cbc       |DES|64|56|CBC|
|EVP_des_ecb       |DES|64|56|ECB|
|EVP_des_ede3_cbc  |DES-EDE3|64|168|CBC|
|EVP_des_ede3_ecb  |DES-EDE3|64|168|ECB|
|EVP_idea_cbc      |IDEA|64|128|CBC|
|EVP_rc4           |RC4||||

### 7) その他のAPI

<br>
以下に共通鍵暗号の処理に関連する主なEVP関数をまとめます。
<br>

|関数名|機能|
|---|---|
|EVP_CIPHER_CTX_iv_length, EVP_CIPHER_iv_length        |IVサイズを取得|
|EVP_CIPHER_CTX_key_length, EVP_CIPHER_key_length      |鍵サイズを取得|
|EVP_CIPHER_CTX_mode, EVP_CIPHER_mode        |暗号、復号のモードを取得|
|EVP_CIPHER_CTX_block_size, EVP_CIPHER_block_size   |ブロックサイズを取得|
|EVP_CIPHER_CTX_flags, EVP_CIPHER_flags       |フラグを取得|
|EVP_CIPHER_CTX_cipher      |アルゴリズムを取得|
|EVP_CIPHER_CTX_set_key_length |鍵サイズを設定|
|EVP_CIPHER_CTX_set_iv      |IVサイズを設定|
|EVP_CIPHER_CTX_set_padding |パディングを設定|
|EVP_CIPHER_CTX_set_flags   |フラグを設定|
|EVP_CIPHER_CTX_clear_flags |フラグをクリア|
|EVP_CIPHER_CTX_reset       |コンテクストをリセット<br>(後方互換：EVP_CIPHER_CTX_FREEで不要に)|
|EVP_CIPHER_CTX_cleanup     |コンテクストをクリーンアップ<br>(後方互換：EVP_CIPHER_CTX_FREEで不要に)|



## 7.5 公開鍵暗号
### 7.5.1 RSA鍵ペア生成

#### 1) 概要
このサンプルプログラムは一対のRSA秘密鍵と公開鍵を生成します。RSA_generate_keyにて内部形式(RSA構造体)で鍵を生成します。これを、i2d_RSAPrivateKey, i2d_RSAPublicKeyにて、DER形式のプライベート鍵、公開鍵に変換し、それぞれのファイルに出力します。

#### 2) コマンド形式と使い方

サンプルプログラムでは以下のアーギュメントを指定します。
- 第1アーギュメント：プライベート鍵のファイル名
- 第2アーギュメント：公開鍵のファイル名


生成したいプライベート鍵(pri.der)、公開鍵のファイル名(pub.der)を指定してサンプルプログラムを起動します。

```
$ ./genrsa pri.der pub.der
```

生成したプライベート鍵、公開鍵の内容をOpenSSLコマンドのrsaサブコマンドを使って確認します。

```
プライベート鍵の確認
$ openssl rsa -in pri.key -inform DER -text -noout
Private-Key: (2048 bit)
modulus:
    00:8c:32:87:e1:0f:51:e5:19:59:59:c7:a6:ff:8f:
    ...
    ff:2a:a1:b4:65:61:01:9b:37:ce:51:bd:b9:0b:ba:
    46:77
publicExponent: 3 (0x3)
privateExponent:
    5d:77:05:40:b4:e1:43:66:3b:91:2f:c4:aa:5f:84:
    ...
    76:f9:91:fc:ec:75:6c:93:3e:97:ea:1a:67:5f:3c:
    bb
prime1:
    00:c1:db:4c:73:80:e5:a3:5c:71:01:11:21:9f:c2:
    ...
    8b:07:53:1d:74:8a:85:8b:73
prime2:
    00:b9:23:b9:bc:64:79:8d:83:7a:ec:44:0a:a5:65:
    ...
    cf:e9:1a:c1:1c:e6:25:df:ed
exponent1:
    00:81:3c:dd:a2:55:ee:6c:e8:4b:56:0b:6b:bf:d6:
    ...
    5c:af:8c:be:4d:b1:ae:5c:f7
exponent2:
    7b:6d:26:7d:98:51:09:02:51:f2:d8:07:18:ee:2e:
    ...
    46:11:d6:13:44:19:3f:f3
coefficient:
    00:80:30:ba:36:30:56:f8:f2:54:48:4d:b5:c0:ac:
    ...
    1d:f9:19:2b:d0:1d:cc:37:db


公開鍵の確認
$ openssl rsa -pubin -in pub.key -inform DER -text -noout
Public-Key: (2048 bit)
Modulus:
    00:8c:32:87:e1:0f:51:e5:19:59:59:c7:a6:ff:8f:
    ...
    ff:2a:a1:b4:65:61:01:9b:37:ce:51:bd:b9:0b:ba:
    46:77
Exponent: 3 (0x3)
```

#### 3) プログラム

RSA_generate_key によってRSA鍵ペアが生成され、鍵ペアへのポインタが返却値として返却されます。生成する鍵の
サイズは第一アーギュメントで指定します。この中に格納された
公開鍵とプライベートをそれぞれi2d_RSAPrivateKeyとi2d_RSAPublicKeyにDER形式でバッファーに取り出します。
取り出されたバッファーへのポインタが第2アーギュメントに返却されます。サンプルプログラムでは、それぞれの鍵を
所定のファイルに出力します。

```
int algo_main( ... )
{

    rsa = RSA_generate_key(RSA_SIZE, RSA_E, NULL, NULL);
    if(rsa == NULL) {
        /* エラー処理 */          
    }
    pri_sz = i2d_RSAPrivateKey(rsa, &pri);
    pub_sz = i2d_RSAPublicKey(rsa, &pub);
    if (pri == NULL || pub == NULL) {
        /* エラー処理 */  
    }
    
    if (fwrite(pub, 1, pub_sz, fpPub) != pub_sz) {
        /* エラー処理 */  
    }

    if (fwrite(pri, 1, pri_sz, fpPri) != pri_sz) {
        /* エラー処理 */  
    }
    ...

}
```

#### 4) 主なAPI
<br>
以下に鍵生成処理に関連する主な関数をまとめます。

<br>

|関数名|機能|
|---|---|
|RSA_generate_key       |RSA鍵ペアを生成|
|i2d_RSA_PrivateKey|RSA秘密鍵データをDER形式で取得|
|i2d_RSA_PublicKey|RSA公開鍵データをDER形式で取得|

<br>

### 7.5.2 RSA暗号化、復号

#### 1) 概要
ここではRSAによる暗号化、復号プログラムの例を紹介します。プログラムは暗号化(rsaEnc.c)と復号(rsaDec.c)の二つにわかれています。

暗号化プログラムでは、暗号化対象メッセージと公開鍵ファイルを読み込み、DER形式の公開鍵を内部形式に変革します。処理コンテクストの確保、
初期化にてパディングスキームを指定し、EVP_PKEY_encryptにてRSA暗号化を実行します。

その際、まずEVP_PKEY_encryptの第2アーギュメント(出力バッファー)にNULLを指定して、メッセージサイズの妥当性を確認します。
このとき、暗号化処理は行われません。次に、出力バッファーポインタを指定してEVP_PKEY_encrypt関数を呼び出し、実際に暗号化処理を実行します。

最後に結果をファイルに出力します。

複合処理の流れは、使用する鍵がプライベート鍵となる点、EVP_PKEY関数はdecryptを呼び出す点を除き、暗号処理と同様です。

#### 2) コマンド形式と使い方

暗号化、復号コマンドでは次のように鍵ファイル、対象メッセージファイルを指定します。


- 暗号化

- 第一アーギュメント：暗号化に使用する公開鍵
- 第2アーギュメント：暗号化されたメッセージ出力ファイル名
- 標準入力：暗号化対象メッセージ


- 復号

- 第一アーギュメント：復号に使用するプライベート鍵
- 第2アーギュメント：復号されたメッセージ出力ファイル名
- 標準入力：復号対象メッセージ


以下の例では、まず暗号化するサンプルメッセージをmsg.txtに格納しておきます。

7.5.1 RSA鍵ペア生成で生成した公開鍵を使ってこれををenc.datに暗号化します。
プライベート鍵を使って暗号化したデータ(enc.dat)をdec.txtに復号します。


```
$ more msg.txt
12345678901234567890
$ ./rsaenc ../04.keyGen/pub.key enc.dat < msg.txt

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
MacBook-Pro-3:05.rsaEnc kojo$ ./rsadec ../04.keyGen/pri.key dec.txt < enc.dat
MacBook-Pro-3:05.rsaEnc kojo$ more dec.txt
12345678901234567890
MacBook-Pro-3:05.rsaEnc kojo$ diff msg.txt dec.txt
```

```
$ ./rsadec ../04.keyGen/pri.key dec.txt < enc.dat
$ diff msg.txt dec.txt
$ more dec.txt
12345678901234567890
```

### 3) プログラム
####  暗号化

```
int algo_main( ... )
{
    if ((msg_sz = fread(msg, 1, BUFF_SIZE, stdin)) < 0) { 
        /* エラー処理 */ }

    if((key_sz = fread(key_buff, 1, sizeof(key_buff), fpKey)) < 0) {  
        /* エラー処理 */  }

    if((pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, key_sz)) == NULL) {  
        /* エラー処理 */  }

    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {  
        /* エラー処理 */  }

    if(EVP_PKEY_encrypt_init(ctx) != SSL_SUCCESS) { 
        /* エラー処理 */  }

    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != SSL_SUCCESS) {
        /* エラー処理 */  }

    if(EVP_PKEY_encrypt(ctx, NULL, &enc_sz, msg, msg_sz) != SSL_SUCCESS) {
        /* エラー処理 */  }
    if (ENC_SIZE != enc_sz) {  
        /* エラー処理 */  }

    if(EVP_PKEY_encrypt(ctx, enc, &enc_sz, msg, msg_sz)!= SSL_SUCCESS) {  
        /* エラー処理 */  }

    if(fwrite(enc, 1, enc_sz, fpEnc) != enc_sz) {
        /* エラー処理 */  }

    ...
}
```

#### 復号

```
int algo_main( ... )
{

    if ((msg_sz = fread(msg, 1, BUFF_SIZE, stdin)) < 0) {
        /* エラー処理 */ }

    if ((key_sz = fread(key_buff, 1, sizeof(key_buff), fpKey)) < 0){
        /* エラー処理 */ }

    if ((pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, key_sz)) == NULL){
        /* エラー処理 */ }

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
        /* エラー処理 */ }

    if (EVP_PKEY_decrypt_init(ctx) != SSL_SUCCESS){
        /* エラー処理 */ }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != SSL_SUCCESS){
        /* エラー処理 */ }

    if (EVP_PKEY_decrypt(ctx, NULL, &dec_sz, msg, msg_sz) != SSL_SUCCESS){
        /* エラー処理 */ }
    if (DEC_SIZE != dec_sz){
        /* エラー処理 */ }

    if (EVP_PKEY_decrypt(ctx, dec, &dec_sz, (const unsigned char *)msg, msg_sz) != SSL_SUCCESS){
        /* エラー処理 */ }

    if (fwrite(dec, 1, dec_sz, fpDec) != dec_sz){
        /* エラー処理 */ }
    ...

}
```

### 3) 使用している主なAPI
<br>
以下に暗号化・複合処理に関連する主な関数をまとめます。

<br>

|関数名|機能|
|---|---|
|d2i_PrivateKey                 |DER形式データから暗号化鍵構造体を生成|
|EVP_PKEY_CTX_new               |暗号化/復号処理用のコンテキスト生成|
|EVP_PKEY_CTX_set_rsa_padding   |パディング方式の指定|
|EVP_PKEY_encrypt_init          |暗号化処理の初期化|
|EVP_PKEY_encrypt               |暗号化処理実行|
|EVP_PKEY_decrypt_init          |復号処理の初期化|
|EVP_PKEY_decrypt               |復号処理実行|
|EVP_PKEY_CTX_free              |暗号化/復号処理用のコンテキスト解放|
|EVP_PKEY_free                  |暗号化鍵構造体を解放|


## 7.5.3 RSA署名/検証

#### 1) 概要

署名:

処理の始めに"EVP_MD_CTX_new"関数により処理コンテクストを管理するための管理ブロックを確保します。次に"EVP_DigestSignInit"関数により初期設定関数で確保したコンテクストに対して鍵、ハッシュアルゴリズム種別などのパラメータを設定します。

"EVP_DigestSignUpdate"関数によって対象メッセージのダイジェストを求めます。メモリーサイズの制限が許す場合は対象メッセージ全体を一括して"EVP_DigestSignUpdate"関数に渡すことができますが、制限がある場合は適当な大きさに区切って"EVP_DigestSignUpdate"関数を複数回呼び出すこともできます。メッセージをすべて読み込んだら、"EVP_DigestSignFinal"関数により求めたダイジェスト値と署名鍵から署名値を求めます。

最後に終了後管理ブロックを解放します。

検証:

処理の始めに"EVP_MD_CTX_new"関数により処理コンテクストを管理するための管理ブロックを確保します。次に"EVP_DigestVerifyInit"関数により初期設定関数で確保したコンテクストに対して鍵、ハッシュアルゴリズム種別などのパラメータを設定します。

"EVP_DigestVerifyUpdate"関数によって対象メッセージのダイジェストを求めます。メモリーサイズの制限が許す場合は対象メッセージ全体を一括して"EVP_DigestVerifyUpdate"関数に渡すことができますが、制限がある場合は適当な大きさに区切って"EVP_DigestVerifyUpdate"関数を複数回呼び出すこともできます。メッセージをすべて読み込んだら、"EVP_DigestVerifyFinal"関数により署名値を検証します。

最後に終了後管理ブロックを解放します。

#### 2) コマンド形式と使い方

以下にEVP関数を使用したRSA署名と検証のサンプルプログラムを示します。このプログラムでは次のコマンドアーギュメントを受け付けます。

#### 署名：rsasig

コマンドアーギュメント：<br>
- 入力ファイル：DER形式の署名鍵ファイル<br>
- 出力ファイル：署名値を出力します。省略した場合、標準出力に出力します。<br>
- 標準入力：署名対象メッセージを入力します


#### 検証：rsaver

コマンドアーギュメント：<br>
- 入力ファイル1：DER形式の検証鍵ファイル<br>
- 入力ファイル2：署名値が格納されたファイル<br>
- 標準入力：署名対象メッセージを入力します

<br><br><br>

サンプルメッセージをmsg.txtに用意します。7.5.1 RSA鍵ペア生成で生成したプライベート鍵を署名鍵としてサンプルデータの署名を生成します。署名はsig.derに出力されます。その署名とサンプルメッセージを入力として署名を検証し、正しく検証されることを確認します。

```
$ ./rsasig ../04.keyGen/pri.key sig.der < msg.txt
$ ./rsaver ../04.keyGen/pub.key sig.der < msg.txt
Signature Verified
```

次に、サンプルメッセージに若干の変更を加えたメッセージ(msg2.txt)を作成し、これを使って改竄されたメッセージでは不正な署名として検出されることを確認します。

```
$ ./rsaver ../04.keyGen/pub.key sig.der < msg2.txt
Invalid Signature
```

#### プログラム

```
署名

int algo_main( ... )
{
    ...
    /* 署名鍵の読み込み */
    key_sz = fread(in, 1, size, infp);
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &inp, key_sz);

    /* 管理ブロックの準備 */
    md = EVP_MD_CTX_new();
    EVP_DigestSignInit(md, NULL, HASH, NULL, pkey);

    /* メッセージを読み込みダイジェストを求める */
    for (; size > 0; size -= BUFF_SIZE) {
        inl = fread(msg, 1, BUFF_SIZE, stdin);
        EVP_DigestSignUpdate(md, msg, inl);
    }

    /* 署名生成 */
    EVP_DigestSignFinal(md, sig, &sig_sz);
    fwrite(sig, 1, sig_sz, outfp) != sig_sz);
```


```
    検証
    /* 検証鍵と署名の読み込み */
    key_sz = fread(pubkey, 1, KEY_SIZE, infp);
    sig_sz = fread(sig, 1, SIG_SIZE, fp2);
    pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, key_sz);

    /* 管理ブロックの確保、設定 */
    md = EVP_MD_CTX_new());
    EVP_DigestVerifyInit(md, NULL, HASH, NULL, pkey) != SSL_SUCCESS) {
        fprintf(stderr, "EVP_DigestVerifyInit\n");
        goto cleanup;
    }

    /* メッセージを読み込みダイジェストを求める */
    for (; size > 0; size -= BUFF_SIZE) {
        inl = fread(msg, 1, BUFF_SIZE, stdin)) < 0);
        EVP_DigestVerifyUpdate(md, msg, inl);

    /* 署名の検証 */
    EVP_DigestVerifyFinal(md, sig, sig_sz) == SSL_SUCCESS)
        printf("Signature Verified\n");
    else
        printf("Invalid Signature\n");
```


### 3) 使用している主なAPI
<br>
以下に署名/検証処理に関連する主な関数をまとめます。

<br>

|関数名|機能|
|---|---|
|d2i_PrivateKey                 |DER形式データから署名/検証鍵構造体を生成|
|EVP_MD_CTX_new                 |署名処理用のコンテキスト生成|
|EVP_DigestSignInit             |署名処理の初期化|
|EVP_DigestSignUpdate           |署名データ更新|
|EVP_DigestSignFinal            |署名処理ファイナライズ|
|EVP_DigestVerifyInit           |署名検証処理の初期化|
|EVP_DigestVerifyUpdate         |署名検証データ更新|
|EVP_DigestVerifyFinal          |署名検証のファイナライズ|
|EVP_PKEY_free                  |署名/検証鍵鍵構造体を解放|
|EVP_MD_CTX_free                |メッセージダイジェスト構造体を解放|

<br>

## 7.8 X509 証明書

ここでは、証明書に関する以下のサンプルプログラムを紹介します。

- 1) CSRの作成
- 2) 自己署名証明書の作成
- 3) 証明書の検証
- 4) 証明書の項目の取り出し

### 7.8.1 CSRの作成

    name = X509_NAME_new();
    509_NAME_add_entry_by_txt(name, "commonName", MBSTRING_UTF8,
                                           (byte*)"wolfssl.com", 11, 0, 1);
    X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_UTF8, (byte*)"support@wolfssl.com", 19, -1, 1);

    d2i_PrivateKey(EVP_PKEY_RSA, NULL, &rsaPriv,
                                        (long)sizeof_client_key_der_2048);
    pub = d2i_PUBKEY(NULL, &rsaPub,
                                   (long)sizeof_client_keypub_der_2048);
    eq = X509_REQ_new();

    X509_REQ_set_subject_name(req, name);
    X509_REQ_set_pubkey(req, pub);
    X509_REQ_sign(req, priv, EVP_sha256());
    i2d_X509_REQ(req, &der), 643);
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
    der = NULL;

    mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, &pkctx, EVP_sha256(), NULL, priv);
    X509_REQ_sign_ctx(req, mctx);

    EVP_MD_CTX_free(mctx);
    X509_REQ_free(NULL);
    X509_REQ_free(req);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);

### 2）検証

    bio = BIO_new_file(csrFile, "rb");
    d2i_X509_REQ_bio(bio, &req);
    pub_key = X509_REQ_get_pubkey(req);
    X509_REQ_verify(req, pub_key);

    X509_free(req);
    BIO_free(bio);
    EVP_PKEY_free(pub_key);

### 3) 使用している主なAPI
<br>
以下に証明書要求処理に関連する主な関数をまとめます。

<br>

|関数名|機能|
|---|---|
|X509_NAME_new              |証明書用名前オブジェクトの確保|
|X509_NAME_add_entry_by_txt |名前オブジェクトにエントリーを追加|
|d2i_PrivateKey             |DER形式データから鍵構造体を生成|
|d2i_PUBKEY                 |公開鍵を抽出|
|X509_REQ_new               |証明書要求オブジェクト生成|
|X509_REQ_set_subject_name  |証明書要求オブジェクトにサブジェクト名追加|
|X509_REQ_set_pubkey        |証明書要求オブジェクトに公開鍵をセット|
|X509_REQ_sign              |証明書署名要求に対して署名|
|i2d_X509_REQ               |証明書要求をDER形式に変換|
|EVP_MD_CTX_new             |メッセージダイジェスト用コンテキスト生成|
|EVP_DigestSignInit         |メッセージダイジェスト初期化|
|X509_REQ_sign_ctx          |メッセージダイジェスト用コンテキストを使って証明書要求に署名|
|X509_REQ_free              |証明書要求オブジェクト解放|
|EVP_PKEY_free              |暗号化鍵構造体を解放|
|EVP_MD_CTX_free            |メッセージダイジェスト構造体を解放|


X509証明書オブジェクトは公開鍵証明書、CSR、CRLの各オブジェクトがサポートされており、それぞれのオブジェクトごとに表のような関数命名規則で機能ごとの関数がサポートされています。


|機能|X509証明書|CSR|CRL|
|---|---|---|---|
|オブジェクト名|X509|X509_REQ|X509_CRL|
|オブジェクト生成|X509_new|X509_REQ_new|X509_CRL_New|
|オブジェクト解放|X509_free|X509_REQ_free|X509_CRL_free|
|項目の設定|X509_set_xxx|X509_REQ_set_xxx|X509_CRL_set_xxx|
|署名|X509_sign|X509_REQ_sign|X509_CRL_sign|
|DERから入力|d2i_X509|d2i_X509_REQ|d2i_X509_CRL|
|DERに出力|id2_X509|id2_X509_REQ|i2d_X509_CRL|
|PEMから入力|PEM_read_X509|PEM_read_X509_REQ|PEM_read_X509_CRL|
|PEMに出力|PEM_write_X509|PEM_write_X509_REQ|PEM_write_X509_CRL|
|PEMから入力|PEM_read_bio_X509|PEM_read_bio_X509_REQ|PEM_read_bio_X509_CRL|
|PEMに出力|PEM_write_bio_X509|PEM_write_bio_X509_REQ|PEM_write__bioX509_CRL|

## 7.8.2 自己署名証明書の作成

### 1) 概要

　このサンプルプログラムでは自己署名証明書を作成します。
あらかじめ準備してある指定された公開鍵、プライベート鍵を読み込みます。次に、X509オブジェクトを生成し、そこに公開鍵、乱数生成したシリアル番号、主体者名、署名者名などの情報を追加します。最後にプライベート鍵で署名し、PEM形式で出力します。

#### 2) コマンド形式と使い方

コマンドアーギュメント：<br>
- アーギュメント１：DER形式の公開鍵<br>
- アーギュメント２：DER形式のプライベート鍵<br>
- 標準出力：PEM形式の自己署名証明書

使用例：

    RSA鍵生成の例で生成した公開鍵とプライベート鍵を指定して自己署名証明書を生成します。

```
$ ./selfsig ../04.keyGen/pub.key ../04.keyGen/pri.key > selfsig.pem
$ openssl x509 -in selfsig.pem  -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            45:82:ac:e9:e0:ff:a2:77:16:1c:a6:86:7b:e9:fd:8c
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=www.wolfssl.com
        Validity
            Not Before: Dec 27 05:08:59 2021 GMT
            Not After : Dec 27 05:08:59 2022 GMT
        Subject: CN=www.wolfssl.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:8c:32:87:e1:0f:51:e5:19:59:59:c7:a6:ff:8f:
                    ...
                    ff:2a:a1:b4:65:61:01:9b:37:ce:51:bd:b9:0b:ba:
                    46:77
                Exponent: 3 (0x3)
    Signature Algorithm: sha256WithRSAEncryption
         16:b9:1f:5c:2b:f9:87:75:53:7d:1b:de:82:39:c8:bc:9e:1f:
            ...
         ec:a9:67:eb:52:3e:8c:da:a7:80:97:20:a6:26:75:9f:36:36:
         cd:23:aa:2d
-----BEGIN CERTIFICATE-----
MIICujCCAaKgAwIBAgIQRYKs6eD/oncWHKaGe+n9jDANBgkqhkiG9w0BAQsFADAa
...
e1Q1ozrvchWsCQhWGMH7Rx6/RF/yecwLlEHt08FZDbthEKK4dXtLCt6UGUzlHws4
NlRHDVBU0jjsqWfrUj6M2qeAlyCmJnWfNjbNI6ot
-----END CERTIFICATE-----
```

### 3) プログラム

```
int algo_main( ... )
{
    /* プライベート鍵、公開鍵の読み込み */
    if ((sz = fread(key_buff, 1, sizeof(key_buff), fpPub)) < 0)
    {    エラー処理 }

    if ((pubkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &key_p, sz)) == NULL)
    {    エラー処理 }

   if ((sz = fread(key_buff, 1, sizeof(key_buff), fpPri)) < 0)
    {    エラー処理 }

    key_p = key_buff;
    if ((prikey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &key_p, sz)) == NULL)
    {    エラー処理 }


    /* 証明書テンプレートの作成 */
    if((x509 = X509_new()) == NULL)
    {    エラー処理 }

    if(X509_set_pubkey(x509, pkey) != SSL_SUCCESS)
    {    エラー処理 }

    if((serial_number = BN_new()) == NULL)
    {    エラー処理 }

    if(BN_pseudo_rand(serial_number, 64, 0, 0) != SSL_SUCCESS)
    {    エラー処理 }

    if((asn1_serial_number = X509_get_serialNumber(x509)) == NULL)
    {    エラー処理 }

    BN_to_ASN1_INTEGER(serial_number, asn1_serial_number);

    /* version 3 */
    if(X509_set_version(x509, 2L) != SSL_SUCCESS)
    {    エラー処理 }

    if((name = X509_NAME_new()) == NULL)
    {    エラー処理 }

    if(X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
        (unsigned char*)"www.wolfssl.com", -1, -1, 0) != SSL_SUCCESS)
    {    エラー処理 }

    if(X509_set_subject_name(x509, name) != SSL_SUCCESS)
    {    エラー処理 }

    if(X509_set_issuer_name(x509, name) != SSL_SUCCESS)
    {    エラー処理 }

    not_before = (long)time(NULL);
    not_after = not_before + (365 * 24 * 60 * 60);
    X509_time_adj(X509_get_notBefore(x509), not_before, &epoch_off);
    X509_time_adj(X509_get_notAfter(x509), not_after, &epoch_off);

    /* テンプレートに署名 */
    X509_sign(x509, prikey, EVP_sha256());

    /* PEM形式で出力 */
    if((sz = PEM_write_X509(stdout, x509)) == 0)
    {    エラー処理 }

}
```

### 4) 主なAPI

|関数名|機能|
|---|---|
|X509_new||
|X509_free||
|X509_set_pubkey||
|BN_new||
|BN_pseudo_rand||
|X509_get_serialNumber||
|BN_to_ASN1_INTEGER||
|X509_set_version||
|X509_NAME_new||
|X509_NAME_add_entry_by_NID||
|X509_set_subject_name||
|X509_set_issuer_name||
|X509_get_notBefore||
|X509_get_notAfter||
|X509_time_adj||
|X509_sign||
|PEM_write_X509||


## 7.8.3 証明書の検証

### 1) 概要

　このサンプルプログラムではX.509証明書の署名をCA証明書で署名検証します。
署名検証対象の証明書と信頼するCA証明書を読み込みます。次にCA証明書の公開鍵を取り出し、対象の証明書を検証し結果を表示します。

#### 2) コマンド形式と使い方

コマンドアーギュメント：<br>
- アーギュメント1：信頼するCA証明書<br>
- アーギュメント2：検証対象の証明書<br>
- 標準出力：
    正当な証明書："Verified"
    不正な証明書："Failed"


使用例：

1) クライアント、サーバサンプルプログラムで使用したCA証明書でサーバ証明書を検証してみます。

```
$ ./verifyCert ../../certs/tb-server-cert.pem ../../certs/tb-ca-cert.pem
Verified
```

2) 次に、サーバ証明書をローカルディレクトリにコピーして一部修正してみます。

```
$ cp ../../certs/tb-server-cert.pem ./tb-server-cert2.pem
```

3) ./tb-server-cert2.pemを修正したのち、両方の証明書のテキストイメージを再生成し差分があることを
確認します。

```
$ openssl x509 -in  ../../certs/tb-server-cert.pem -text > ./tb-server-cert.txt
$ openssl x509 -in  ./tb-server-cert2.pem -text > ./tb-server-cert2.txt
$ diff ./tb-server-cert.txt ./tb-server-cert2.txt
45c45
<          74:62:d8:6d:21:11:eb:0c:82:50:22:a0:c3:88:52:7c:b3:c4:
---
>          74:62:d8:6d:21:11:eb:0c:82:50:22:a4:c3:88:52:7c:b3:c4:
69c69
< oMOIUnyzxOk4dRH+SkcmN8pW17Wp2WbS45BiHjVtgrAALMTv2dJpk8mQUjYQTTyF
---
> pMOIUnyzxOk4dRH+SkcmN8pW17Wp2WbS45BiHjVtgrAALMTv2dJpk8mQUjYQTTyF
```

4) 修正したサーバ証明書を検証します。

```
$ ./verifycert ../../certs/tb-ca-cert.pem  ./tb-server-cert2.pem
Failed
```


### 3) プログラム

```
int algo_main( ... )
{
    if ((certSv = PEM_read_X509(fpSv, 0, 0, 0)) == NULL)
    {    エラー処理 }

    if((certCA = PEM_read_X509(fpCA, 0, 0, 0 )) == NULL)
    {    エラー処理 }

    if((pkey = X509_get_pubkey(certCA)) == NULL)
    {    エラー処理 }

    if(X509_verify(certSv,pkey) == SSL_SUCCESS)
        printf("Verified\n");
    } else {
        printf("Failed\n");
    }
```


### 4) 主なAPI

|関数名|機能|
|---|---|
|PEM_read_X509||
|X509_get_pubkey||
|X509_verify||


## 7.8.4 証明書項目の取り出し

### 1) 概要
このサンプルプログラムではX.509証明書の項目を取り出し方法の例として、Common Nameを取り出し表示します。


#### 2) コマンド形式と使い方

コマンドアーギュメント：<br>
- アーギュメント1：サンプル証明書<br>
- 標準出力：
    取り出した文字列


使用例：

```
$ ./certName  ../../certs/tb-ca-cert.pem
CN: www.wolfssl.com
```

### 3) プログラム

```
int main(int argc, char **argv)
{

    if((x509 = X509_load_certificate_file(argv[1], WOLFSSL_FILETYPE_PEM)) == NULL) 
    {   エラー処理 }

    if((name = X509_get_subject_name(x509)) == NULL)
    {   エラー処理 }

    if((idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1))  == -1)
    {   エラー処理 }

    if((ne = X509_NAME_get_entry(name, idx)) == NULL)
    {   エラー処理 }

    if((asn = X509_NAME_ENTRY_get_data(ne)) == NULL)
    {   エラー処理 }

    if((subCN = (char*)ASN1_STRING_data(asn)) == NULL)
    {   エラー処理 }
    
    printf("CN: %s\n", subCN);
}

```

### 主なAPI

|関数名|機能|
|---|---|
|X509_load_certificate_file||
|X509_get_subject_name||
|X509_NAME_get_index_by_NID||
|X509_NAME_get_entry||
|X509_NAME_ENTRY_get_data||
|ASN1_STRING_data||


### 参考

X.509証明書の項目を指定して項目へのポインタを取得することができます。表に主なAPIをまとめます。

|関数名|項目名|
|---|---|
|X509_get_serialNumber||
|X509_get_subject_name||
|X509_get_issuer_name||
|X509_get_notAfter||
|X509_get_notBefore||
|X509_get_pubkey||
|X509_get_version||

