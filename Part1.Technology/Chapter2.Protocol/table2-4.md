|用途|導出関数|入力 ( IKM引数,|入力シークレット,|ラベル,|メッセージ )|出力 (生成シークレット or 導出される鍵)|
|:--|:--|:--:|:--:|:--:|:--:|:--|
|0-RTT||||||
||HKDF-Extract|PSK|0|-|-|EarlySecret(ES)|
||HKDF-Expand|-|ES|"ext binder\"\| \"res binder"|-|binder_key|
||HKDF-Expand|-|ES|"e exp master"|ClientHello|early_exporter_master_secret|
||HKDF-Expand|-|ES|"c exp master"|ClientHello|client_early_traffic_secret|
|ハンドシェーク|||||||
||HKDF-Extract|(EC)DHE|ES|"derived"|-|HandshakeSecret(HS)||
||HKDF-Expand|-|HS|"c hs traffic"|ClientHello ~ ServerHello|client_handshake_traffic_secret|
||HKDF-Expand|-|HS|"s hs traffic"|ClientHello ~ ServerHello|server_handshake_traffic_secret|
|アプリ・データ|||||||
||HKDF-Extract|0|HS|"derived"|-|MasterSecret(MS)||
||HKDF-Expand|-|MS|"c ap traffic"|ClientHello ~ server Finished|client_application_traffic_secret_0|
||HKDF-Expand|-|MS|"s ap traffic"|ClientHello ~ server Finished|server_application_traffic_secret_0|
||HKDF-Expand|-|MS|"exp master"|ClientHello ~ server Finished|exporter_master_secret|
||HKDF-Expand|-|MS|"res master"|ClientHello ~ server Finished|resumption_master_secret|
