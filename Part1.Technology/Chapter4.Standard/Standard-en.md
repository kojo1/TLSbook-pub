## Chapter 4 Standards Supporting TLS

The IETF (Internet Engineering Task Force) is a standardization organization that aims to standardize Internet protocols, and has established many basic protocol standards for the Internet, including TCP / IP. These standards are published in the form of RFCs (Request For Comments). For example, the gist of TLS 1.3 is summarized in RFC8446.

However, the details are defined in each individual RFC. Also, their definitions may be based on the standards of another standards body. Therefore, in order to correctly understand the standards of the TLS protocol, it may be necessary to go back to the relationships between these regulations and the underlying standards.

In this chapter, we will take a bird's-eye view of the relationship between the standard regulations related to TLS.

### 4.1 Standardization by IETF

The IETF (Internet Engineering Task Force) is a standardization organization that aims to standardize Internet protocols, and has established many basic protocol standards for the Internet, including TCP / IP. These standards are published in the form of RFCs (Request For Comments). Version 1.0 of TLS was also formulated as RFC 2246, and after subsequent revisions, it has become TLS 1.3 by today's RFC 8446.

Table 4.1 shows the RFCs related to TLS and DTLS (☆ Footnote: Protocols for achieving datagram protocol security, such as UDP).

[Table 4.1 TLS / DTLS related RFC]
| Technical Fields | RFC Numbers | Descriptions | Remarks |
|-|-|-|-|
| SSL / TLS ||||
|| 6101 | Secure Sockets Layer (SSL) Protocol Version 3.0 ||
|| 2246 | TLS Protocol v1.0 | Obsolete by RFC 4346 |
|| 4346 | TLS Protocol v1.1 | Obsolete by RFC 5246 |
|| 5246 | TLS Protocol v1.2 | Obsolete by RFC 8446 |
|| 8446 | TLS Protocol v1.3 |
|| 6176 | Prohibition of Secure Sockets Layer (SSL) version 2.0 ||
|| 7568 | Secure Sockets Layer (SSL) version 3.0 obsolete |
|| 8996 | Abolition of TLS 1.0 and TLS 1.1 |
| DTLS ||||
|| 4347 | Datagram Transport Layer Security | Obsolete by RFC 6347 |
|| 6347 | Datagram Transport Layer Security Version 1.2 |
|| Draft | Datagram Transport Layer Security Version 1.3 |

The details of these protocol specifications are also specified and referenced as separate RFCs. Table 4.2 summarizes the RFCs that specify the details of TLS 1.3.

[Table 4.2 Individual RFCs Referenced by TLS RFCs]
| Technical Fields | RFC Numbers | Descriptions | Remarks |
|-|-|-|-|
| TLS extension ||||
|| 6066 | TLS Extensions: Extension Definitions |
|| 4366 | TLS Extension | Obsolete by RFC 6066 |
|| 6520 | TLS and DTLS Heartbeat Extensions |
|| 8449 | TLS record size limit expansion |
|| 7627 | TLS Session Hash and Extended Master Secret Extension |
|| 7685 | TLS Client Hello Padding Extension |
|| 7924 | TLS cache information expansion |
|| 7301 | TLS Application Layer Protocol Negotiation Extension |
|| 8422/7919 | Supported Elliptic Curve Cryptographic Group Extensions ||
|| 5746 | TLS Re-Negotiating Statement Extension |
|| 7250 | Client-supported certificate type extensions ||
| OCSP ||||
|| 6960 | Online Certificate Status Protocol (OCSP) |
|| 6961 | Multiple Certificate Status Request Extensions | Obsolete by RFC 8446 |
|| 6692 | Certificate Transparency, Signed Certificate Timestamp Extension ||
|| 8954 | OCSP nonce extension ||
| Random numbers ||||
|| 4086 | Randomness requirements for security |
| Hash ||||
|| 3174 | US Secure Hash Algorithm 1 (SHA1) |
|| 4634 | US Secure Hash Algorithms (SHA and HMAC-SHA) | Obsolete by RFC 6234 |
|| 6234 | US Secure Hash Algorithm (SHA, SHA-based HMAC, HKDF) |
| Common key cryptography ||||
|| 1851 | ESP 3DES Tansform ||
|| 3602 | AES-CBC algorithm and its use in IPsec ||
|| 3686 | Using AES-CTR mode as ESP for IPsec |
|| 5288 | AES-GCM Cipher Suite for TLS |
|| 6655 | AES-CCM Cipher Suite for TLS |
|| Draft | RC4 |
|| 7465 | Prohibition of RC4 Cipher Suite |
|| 5932 | Camellia Cipher Suite for TLS |
|| 8439 | ChaCha20 and Poly1305 for IETF Protocols |
|| 5116 | Interfaces and algorithms for authenticated encryption |
| Key derivation ||||
|| 5705 | Key element export for TLS |
|| 5869 | HMAC-based Extract-Expanded Key Derivation Function (HKDF) |
|| 8018 | Password-based key derivation (PBKDF2) |
| RSA ||||
|| 8017 | PKCS # 1: RSA encryption version 2.2 |
|| 5756 | RSA-OAEP and RSA RSASSA-PSS algorithm parameter updates |
| Elliptic curve ||||
|| 7748 | Elliptic curve for security |
|| 8422 | Elliptic Curve Cryptographic Suite before TLS 1.2 |
| Key agreement ||||
|| 7250 | Using Raw Public Keys with TLS and DTLS |
|| 7919 | TLS negotiated finite field DH temporary parameters |
| Signature ||||
|| 6979 | Usage of Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA) |
|| 8032 | Edwards Curve Digital Signature Algorithm (EdDSA) |
| Certificate ||||
|| 3647 | Internet X.509 Certificate Policy and Authentication Framework by PKI |
|| 5280 | X.509 Public Key Infrastructure Certificates and Certificate Revocation List (CRL) Profiles |

### 4.2 Public-Key Cryptography Standards (PKCS)

PKCS is a set of standards established by RSA Security, Inc. from the early stages of public key cryptography with the aim of defining PKI (Public Key Infrastructure) as a concrete standard. Today, much of it has been taken over by the IETF RFCs and referenced as the basis for Internet Protocol standards (Table 4.4).

[Table 4.4 PKCS and RFC]
PKCS number | RFC number | Content |
|-|-|-|
| # 1 | 8017 | RSA cryptographic scheme |
| # 2 |-| Integrated into PKCS # 1 and abolished |
| # 3 |-| Diffie-Hellman Key Sharing |
| # 4 |-| Integrated into PKCS # 1 and abolished |
| # 5 | 8018 | Password-based key derivation (PBKDF2) |
| # 6 |-| Extended syntax for X.509 certificate v1. Discarded by X.509 v3 |
| # 7 | 5652 | Cryptographic Message Syntax (CMS) |
| # 8 | 5958 | Syntax of private key information |
| # 9 | 2985 | Selected object class, attribute type |
| # 10 | 2986/5967 | Certificate Signing Request (CSR) |
| # 11 || Cryptographic token interface. API for HMS (Hardware Security Module) |
| # 12 | 7292 | File protection with password-based encryption. Syntax for exchanging personal information |
| # 13 |-| Elliptic curve cryptography |
| # 14 |-| Pseudo-random numbers |
| # 15 |-| Cryptographic token format |

### 4.3 X.509

X.509 is a broad standard for PKI (Public Key Infrastructure) defined by ITU-T (☆ Footnote: ITU (International Telecommunications Union) Telecommunication Sector) and TLS. It is used as a standard for public key certificates. The first version of X.509 was released in 1988 and has since been revised to v2 and v3. The IETF refers to v3 and specifies it as RFC 5280. Note that TLS requires the use of X.509 v2 or v3.

ASN.1 (Abstract Syntax Notation One) is used to express data used in networks and computers, including X.509, as a set of general-purpose variable-length records, and to strictly define the data format. It is standard. It was originally developed as part of the X.409 Recommendation by the CCITT (Comité Consultatif International Télégraphique et Téléphonique). After that, it was revised to the X.208 and X.680 series, and it has been taken over to the present day, but the name of ASN.1 is still widely used today.

ASN.1 only specifies the logical representation of the data. Therefore, encoding rules are required to map it to a physical data structure, and BER (Basic Encoding Rules), DER (Distinguished Encoding Rules), etc. are defined. The PEM (Privacy Enhanced Mail) encoding rules, which are widely used together with DER, were established by the IETF as encoding rules for improving the confidentiality of mail messages.

## 4.4 Standards by NIST

The National Institute of Standards and Technology (NIST) has set guidelines and recommendations for the SP-800 (Special Publication 800) series and the FIPS Pub (Federal Information Processing Standards Publication) series for computer security. We are publishing a document. Although these documents are regulated by the US federal government and are not international standards, many documents refer to them as the basis for standards on the Internet and are incorporated into international standards.

[Table 4.5 ☆☆☆]
Documents | Contents | Titles |
| --- | --- | --- |
SP800-38D | GCM / GMAC | Recommendation for Block Cipher Modes of Operation: Galois / Counter Mode (GCM) and GMA |
SP800-38C | CCM | Recommendation for Block Cipher Modes of Operation: the CCM Mode for Authentication and Confidentiality |
SP800-38B | CMAC | Recommendation for Block Cipher Modes of Operation: the CMAC Mode for Authentication |
SP800-38A | CBC | Recommendation for Block Cipher Modes of Operation: Three Variants of Ciphertext Stealing for CBC Mode |
SP800-52 Rev. 2 | TLS Usage Guidelines | Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations (2nd Draft) |
SP800-56C | Key Derivation | Recommendation for Key-Derivation Methods in Key-Establishment Schemes |
SP 800-90A | Pseudo-random numbers | Recommendation for Random Number Generation Using Deterministic Random Bit Generators |
SP 800-90B | Intrinsic Random | Recommendation for the Entropy Sources Used for Random Bit Generation |
SP 800-131A REV. 2 | Key Lengths | Transitioning the Use of Cryptographic Algorithms and Key Lengths |
| FIPS PUB 197 | AES | Advanced Encryption Standard (AES) |
FIPS PUB 198-1 | HMAC | The Keyed-Hash Message Authentication Code (HMAC) |
FIPS 186-4 | DSS | Digital Signature Standard (DSS) |
| FIPS 180-4 | SHA-1, SHA-2 | Secure Hash Standard (SHS) |
FIPS 202 | SHA-3 | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions |
FIPS 140-2 / 3 | Security Requirements for Cryptographic Modules | 
More about this source textSource text required for additional translation information
