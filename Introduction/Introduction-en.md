## Introduction: From SSL to TLS

### De facto standard SSL
SSL was developed by Netscape Communications, a leading vendor of web browsers that was rapidly becoming popular at the time, and implemented in their browsers. Although important vulnerabilities were discovered in early versions, SSL3.0 provided in 1996 was significantly improved in terms of security at that time and became widely used as the de facto standard in the early days of the Internet. became.

### Neutral standard TLS
On the other hand, with the rapid spread of the Internet, awareness of the need for protocol standards that do not depend on specific companies has increased. With the recognition of the importance of security, the foundation of the IETF is being solidified as a standard-making organization, and in 1996, the IETF started to formulate TLS specifications. However, although the first version, TLS 1.0, was meaningful as a standard protocol by a neutral organization, it is not much different from SSL 3.0, which was already widespread at that time, but it is not compatible and widespread. Did not reach.

### Standard maturity
In the world of the Internet, new attack methods and risk of vulnerability at the protocol specification level have been pointed out one after another, and TLS has continued to make revision efforts at the IETF. In the process of issuing TLS1.1 (RFC-4346) in 2006 and TLS1.2 (RFC-5246) in 2008, the requirements required for the security protocol specification gradually became clear, and the robustness of the protocol became clear. Also increased. In addition, we have established a mechanism to flexibly respond to the constantly evolving attack methods, security, and cryptographic technologies, and TLS has become indispensable as a standard protocol that forms the core of Internet security. rice field.

### Considering a new TLS
However, on the other hand, there are concerns about the increase in complexity due to maintaining backward compatibility in the process of evolution and the risk of new potential vulnerabilities, and in 2013, it was a compilation based on past experience and achievements. As a new major version upgrade, consideration for TLS 2.0 has started. However, since the TLS version information is embedded in the TLS records that go to and from the actual network, it turned out that it was extremely difficult to raise the major version smoothly soon after the start of consideration. Although we will stick to the examination goal as it is, we have decided to use the name of TLS 1.3 and minor version upgrade as the name of the version.

For that reason, the name of the version is conservative, but the protocol specification finally issued as a standard in 2018 is comparable to a major version upgrade that wipes out the concerns so far as originally targeted. The specifications have been revised.

### New security risks and threats
Meanwhile, it was discovered that a large-scale systematic network communication interception and information gathering that had not been known until now were known, and that a private key that should never be leaked due to a bug in the server software was leaked. There were also serious incidents that shook the foundation of security. It has been pointed out that public key cryptography, which has been considered secure until now, needs to be reviewed, and a new dimension of security such as complete forward secrecy (see Chapter 5 Security Issues) has been pointed out. The need has come to be recognized.

### New cryptography
During that time, research on new cryptographic algorithms has progressed, and algorithms with much higher processing efficiency than before have become practically available as well as security. Such individual algorithms have been gradually introduced as standard in TLS 1.2, and old compromised algorithms have been gradually abolished, but they have not been wiped out of risky algorithms due to backward compatibility. .. In addition, formal verification and verification tools for protocols and cryptographic algorithms are beginning to appear that are effective for actual verification.

| Name | Attack Method | Cause | Solution |
| --- | ---- | ---- | ---- |
|SLOTH | Hash collisions | Hazardous hashes | Algorithm obsolete |
| SWEET32 | Block Cipher Collision | Threatened Common Key Cryptography | Algorithm Abolition |
|CurveSwap | Downgrade | Signature Range | Signature Range Expansion |
|LogJam | Downgrade | Signature Scope | Signature Scope Expansion |
|FREAK | Downgrade | Signature Scope | Signature Scope Expansion |
|POODLE | Padding Oracle | Common Key Cryptography and MAC | AEAD |
|BEAST | Padding Oracle | Symmetric-key cryptography and MAC | AEAD |
|Lucky 13 | Padding Oracle | Common Key Cryptography and MAC | AEAD |
|Lucky Microseconds | Padding Oracle | Symmetric Key Cryptography and MAC | AEAD |
|WeakDH | DH parameters | Degrees of freedom of DH parameters | Support group |
|pen-and-paper | RSA padding | PKCS # v1.5 | PSS |
|ROBOT | RSA private key | static RSA | temporary key DH |
|million-message | RSA private key | static RSA | temporary key DH |

            The main attack methods and vulnerabilities that motivated TLS 1.3

### TLS1.3
Against this background, TLS 1.3, which was officially issued in August 2018, abandoned the backward compatibility so far and realized a bold arrangement of protocol specifications. Of course, it is impossible to upgrade the protocols around the world that are actually used every day at once. In terms of implementation, it is possible to migrate to the new version while accepting the old version of TLS. However, for communication sessions established between the new TLS 1.3, security risks are eliminated as much as possible, and improvements are expected in terms of performance. Below are some of the safety and performance improvements in TLS 1.3.

#### Improved safety

- Encrypt most of the handshake
- Organize encryption algorithms
- Abolition of dangerous functions such as downgrade and compression
- From the viewpoint of complete forward secrecy, static public keys are excluded, and only temporary keys Diffie-Hellman are used.
― The common key cryptography is narrowed down to only those with an authentication key (AEAD: see Chapter 3 Cryptography Algorithm).

    Along with these, the cipher suites have been significantly narrowed down and the cipher suite notation has been organized.


#### Performance improvements
- Reduction of round trips and latency by organizing hand shakes
- A new cryptographic algorithm with high processing efficiency, formal standardization of elliptic curves


Both SSL and TLS are still used as synonyms for handshakes performed on clients and servers. However, SSL as a term for protocol specifications is now a past specification and is not used in actual products. TLS has continued to evolve since then, and TLS 1.3 has achieved a prima facie culmination. Based on this recognition, this document will explain based on TLS 1.3 unless otherwise specified.

It can be said that TLS 1.3 has become a highly complete standard as a protocol specification. However, in order to realize secure network communication as a whole system, it is necessary to realize high quality at the library layer that realizes a secure protocol, and to correctly understand and use the security and protocol on the application side that uses it. In addition, it is necessary to realize reliable security at all layers such as the application and system operation method.

The knowledge that application engineers need to understand the TLS library correctly and realize a secure system is diverse and tends to be distributed to their respective disciplines, technology layers, and so on. This book aims to organize and explain such knowledge so that it can be understood in a consistent manner. 
More about this source textSource text required for additional translation information
Send feedback
Side panels