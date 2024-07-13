# SecureRSA

## Introduction

RSA encryption, named after its inventors Ron Rivest, Adi Shamir, and Leonard Adleman, is a public-key cryptographic algorithm widely used for securing digital communication. It ensures data Confidentiality, Integrity, and Authentication (CIA) over insecure channels such as the internet. RSA encryption is foundational to many security protocols and applications, making it crucial in modern cryptography.

## Features

- **Key Generation**: Generate public and private keys using large prime numbers.
- **Encryption**: Securely encrypt messages using the recipient's public key.
- **Decryption**: Decrypt received messages using the private key.
- **Digital Signatures**: Create and verify digital signatures to ensure message authenticity and integrity.
- **Secure Data Transmission**: Protect sensitive information during transmission over insecure channels.
- **Integration with Protocols**: Support for protocols like SSL/TLS and secure email systems (e.g., PGP, S/MIME).

## Industrial Applications

- **Data Transmission**: Secure data transmission over the internet, protecting financial transactions and personal data.
- **Digital Signatures**: Ensure authenticity and integrity of messages and documents.
- **Secure Email**: Encrypt email contents and verify digital signatures.
- **SSL/TLS Protocols**: Secure web browsing by establishing a secure connection between client and server.

## Conclusion

RSA encryption is a cornerstone of modern cryptography, providing robust security mechanisms for data transmission, digital signatures, and secure communications. Its mathematical foundation and practical applications make it an indispensable tool for ensuring confidentiality, integrity, and authenticity in various industrial settings.

## Example

### Key Generation
- **Select Primes**: \( p = 61 \), \( q = 53 \)
- **Compute n**: \( n = 61 \times 53 = 3233 \)
- **Compute φ(n)**: \( φ(n) = (61-1) \times (53-1) = 3120 \)
- **Choose e**: \( e = 17 \)
- **Compute d**: \( d \times e \equiv 1 \ (\text{mod} \ 3120) \), \( d = 2753 \)

### Encryption
- **Plaintext Message**: \( m = 65 \)
- **Ciphertext Calculation**: \( c = 65^{17} \ (\text{mod} \ 3233) = 2790 \)

### Decryption
- **Received Ciphertext**: \( c = 2790 \)
- **Plaintext Recovery**: \( m = 2790^{2753} \ (\text{mod} \ 3233) = 65 \)
