|方式|TLS<br>バージョン|フェーズ|説明|
|---|---|---|---|
|セッションID|TLS1.2以前|要求|ClientHelloのSessionID拡張にて要求|
|          |      |応答|ServerHelloのSessionIDにてIDを返却|
|          |      |セッション<br>再開|ClientHelloのSessionIDにてIDを指定|
|          |TLS1.3||廃止|
||
|セッションチケット|TLS1.2以前<br>RFC 5077|要求|ClientHelloのセッションチケット拡張にて要求|
|               |      |応答|ServerHelloのセッションチケット拡張にて応答|
|               |      |チケット<br>送付|ハンドシェーク後尾のNewSessionTicketにて送付|
|               |      |セッション<br>再開|ClientHelloのセッションチケット拡張にて指定|
|               |TLS1.3|   |セッションチケット拡張の廃止|
|               |      |要求|クライアントからのチケット要求の廃止<br>発行の有無はサーバ側の判断に|
|               |      |送付|ポストハンドシェークの<br>NewSessionTicketメッセージにて送付|
|               |      |セッション<br>再開|PSKの0-RTTメッセージとしてチケットを送付|


<div style="text-align: center;">
<br>
表2-4 セッション再開方式の比較

</div>