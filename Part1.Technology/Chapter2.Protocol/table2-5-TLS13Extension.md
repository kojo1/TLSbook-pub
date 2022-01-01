## TLS 1.3のTLS拡張一覧
<br>

|拡張タイプ| 概要|RFC|拡張が含まれるTLSメッセージ|
|:--:|:--:|:--|:--:|
|server_name<br>(SNI)|セッション再開時の照合要素として利用|6066|ClientHello, EncryptedExtensions|
|max_fragment_length|メッセージの最大フラグメントサイズ|6666|ClientHello, EncryptedExtensions|
|status_request|OCSP証明書ステータスを要求|6666|ClientHello, CertificateRequest, Certificate|
|supported_groups|使用したい鍵交換スキームリスト|8422, 7919|ClientHello, EncryptedExtensions|
|signature_algorithms|署名アルゴリズム|8446|ClientHello, CertificateRequest|
|signature_algorithms_cert|証明書の署名アルゴリズム|8446|ClientHello, CertificateRequest|
|use_srtp|SRTPプロファイルのリスト|5764|ClientHello, EncryptedExtensions|
|heartbeat|ハートビートの送信モードの提示|6520|ClientHello, EncryptedExtensions|
|application_layer_protocol_negotiation|ALPNサポートプロトコル名のリスト|7301|ClientHello, EncryptedExtensions|
|signed_certificate_timestamp|OCSP証明書ステータスのタイムスタンプ|6962|ClientHello, CertificateRequest, Certificate|
|client_certificate_type|クライアント証明書フォーマット|7250|ClientHello, EncryptedExtensions|
|server_certificate_type|サーバ証明書フォーマット|7250|ClientHello, EncryptedExtensions|
|padding|パディング拡張|7685|ClientHello|
|psk_key_exchange_modes|PSKのみ/鍵交換付きPSKの提示|8446|ClientHello|
|pre_shared_key|PSK拡張|8446|ClientHello, ServerHello|
|early_data|EarlyData拡張|8446|ClientHello, EncryptedExtensions, NewSessionTicket|
|supported_versions|サポートしているTLSバージョン|8446|ClientHello, ServerHello, HelloRetryRequest|
|cookie|ClientHelloリトライクッキー|8446|ClientHello, HelloRetryRequest|
|certificate_authorities|サポートしてるCAリスト|8446|ClientHello, CertificateRequest|
|oid_filters|証明書拡張OIDと値の組|8446|CertificateRequest|
|post_handshake_auth|サーバに対してポストハンドシェーク認証を許可|8446|ClientHello|
|key_share|鍵交換スキーム用パラメターのリスト|8446|ClientHello, ServerHello, HelloRetryRequest|
