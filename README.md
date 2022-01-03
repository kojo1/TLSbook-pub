![Cover](./Cover.png)

# Table of contents
# Part 1 Technology
## Chapter 1 Simple TLS program
### 1.1 TCP client / server
### 1.2 Add TLS layer
### 1.3 A bird's-eye view of the TLS protocol
### 1.4 Full Handshake Message Summary

## Chapter 2. Protocol
## 2.1 Full hand shake
### 2.1.1 Overview
### 2.1.2 Cipher Suite Agreement
### 2.1.3 Hello Retry
### 2.1.4 Key agreement
### 2.1.5 Key derivation
### 2.1.6 Peer authentication
### 2.1.7 Certificate Status Information: OCSP Stapling
## 2.1.8 Other TLS extensions
## 2.2 Pre-shared key and session restart
### 2.2.1 Pre-shared key (PSK)
### 2.2.2 Session resume
### 2.2.3 Early Data
## 2.3 Message after handshake
## 2.4 Record Protocol
## 2.5 Alert Protocol

## Chapter 3. Crypto
### 3.1 Overview
### 3.2 Random numbers
### 3.3 Hash
### 3.4 Symmetric key cryptography
### 3.5 Key derivation
### 3.6 Public Key and Key Agreement
### 3.7 Elliptic curve
### 3.8 Public Key Certificate
### 3.9 Public Key Infrastructure (PKI)

## Chapter 4 Standards
### 4.1 Standardization by IETF
### 4.2 Public-Key Cryptography Standards (PKCS)
### 4.3 X.509
### 4.4 Standards by NIST

## Chapter 5 Security Considerations
### 5.1 Vulnerability
### 5.2 Threats and Attack Techniques
### 5.3 Key management
### 5.5 Incident Management

# Part2. Programming
## Chapter 6 Protocol
### 6.1 Client/Server
### 6.2 TLS Extension
### 6.3 Pre-shared key (PSK)
### 6.4 Resume session
### 6.5 Early Data (0-RTT)

## Chapter 7. Crypto Algorithm
### 7.1 Common wrapper
### 7.2 Hash
### 7.3 Message verification code
### 7.4  Symmetric key cryptography
### 7.5 Public Key Cryptography
### 7.8 Creating a CSR
### 7.9 Creating a self-signed certificate
### 7.10 Certificate verification
### 7.11 Extraction of certificate items

## Chapter 8. Configuration
### 8.1 Proprietary network messaging
### 8.2 Platform without file system
### 8.4 Super Loop

# Part 3 Library structure
## Chapter 9 Insight
### 9.1 Configuration and file organization

## Chapter 10 Protocol
### 10.1 TLS connection
### 10.2 Non-blocking mode

## Chapter 11 Crypto
### 11.1 Overview
### 11.2 AES block cipher
### 11.3 optimizating AES
### 11.4 Public key crypto
### 11.5 Optimizing public key crypto

## Chapter 12 Platform Dependencies
### 12.1 Overview
### 12.2 Thread / task exclusive control
### 12.3 File system
### 12.4 Network
### 12.5 Real time clock
### 12.6 Heap memory management
### 12.7 Intrinsic random numbers, random number seeds