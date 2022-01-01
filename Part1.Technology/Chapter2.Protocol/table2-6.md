|Type|拡張の名称|概要|RFC|含むTLSメッセージ|CH|SH|CR|CT|EE|HRR|NST|
|--:|:--|:--|:--|--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
|0|server_name|セッション再開時の照合要素として利用|6066||✓| | | |✓|||
|1|max_fragment_length|メッセージの最大フラグメントサイズ|6066,8449||✓| | | |✓|||
|5|status_request|OCSPによるレスポンスを要求|6960||✓| |✓|✓|||
|10|supported_groups|使用したい鍵交換スキームリスト|8422,7919||✓| | | |✓|||
|13|signature_algorithms|署名アルゴリズム|8446||✓| |✓|||||
|14|use_srtp|SRTPプロファイルのリスト|5764||✓| | | |✓|||
|15|heartbeat|ハートビートの送信モードの提示|6520||✓| | | |✓|||
|16|application_layer_protocol_negotiation|ALPNサポートプロトコル名のリスト|7301||✓| | | |✓|||
|18|signed_certificate_timestamp|OCSP証明書ステータスのタイムスタンプ|6962||✓| |✓|✓||||
|19|client_certificate_type|クライアント証明書フォーマット|7250||✓| | | |✓|||
|20|server_certificate_type|サーバ証明書フォーマット|7250||✓| | | |✓|||
|21|padding              |パディング拡張|7685||✓| | | ||||
|41|pre_shared_key       |PSK拡張|8446||✓|✓| | ||||
|42|early_data           |EarlyData拡張|8446||✓| | | |✓||✓|
|43|supported_versions   |クライアントがサポートしているTLSバージョン提示|8446||✓|✓| | ||✓||
|44|cookie               |ClientHelloリトライクッキー|8446||✓| | | ||✓||
|45|psk_key_exchange_modes|PSKのみ/鍵交換付きPSKの提示|8446||✓| | | ||||
|47|certificate_authorities|サポートしてるCAリスト|8446||✓| |✓| ||||
|48|oid_filters          |証明書拡張OIDと値の組|8446||| |✓| ||||
|49|post_handshake_auth  |サーバに対してポストハンドシェーク認証を許可|8446||✓| | | ||||
|51|key_share            |各鍵交換スキーム用パラメターのリスト|8446||✓|✓| | ||✓||

<br>
TLSメッセージ　CH : ClientHello,　SH : ServerHello,　CR : CertificateRequest,　CT : Certificate,　EE : EncryptedExtension,　HRR : HelloRetryRequest,　NST : NewSessionTicket
