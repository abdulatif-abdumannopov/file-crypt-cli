# File Crypt CLI

**Secure File Encryption, Decryption, and Hashing Tool**  

`File Crypt CLI` is a lightweight, high-performance command-line tool designed for professional-grade file encryption, decryption, and integrity verification. Built with OpenSSL, it leverages **AES-256-GCM** for authenticated encryption and **SHA-256** for secure hashing, ensuring your sensitive data is fully protected.


## Features

- **AES-256-GCM File Encryption**: Encrypt any file with a password. AES-GCM provides both confidentiality and integrity using a 256-bit key.
- **AES-256-GCM File Decryption**: Safely decrypt files with the correct password. Automatic verification ensures file integrity before returning plaintext.
- **SHA-256 File Hashing**: Quickly generate a cryptographic hash for integrity checks, digital fingerprinting, or verification purposes.
- **Command-line Simplicity**: Designed for quick usage in scripts or pipelines, no GUI needed.


## Installation

Compile the program using GCC with OpenSSL support:

```bash
gcc main.c -o file_crypt_cli -lssl -lcrypto
```

# Usage
## Encrypt a File
```bash
./file_crypt_cli -e -f filepath -o output -p password
```

- <p><b>-e</b> Encrypt mode</p>
- <p><b>-f</b> File path</p>
- <p><b>-o</b> Output file</p>
- <p><b>-p</b> password</p>

## Decrypt a File
```bash
./file_crypt_cli -d -f filepath -o output -p password
```

- <p><b>-d</b> Decrypt mode</p>
- <p><b>-f</b> File path</p>
- <p><b>-o</b> Output file</p>
- <p><b>-p</b> password</p>

## Generate SHA-256 Hash
```bash
./file_crypt_cli -h -f filepath
```

- <p><b>-d</b> Hasht mode</p>
- <p><b>-f</b> File path</p>

### Output example
```
49fac0c6df7f0c38efbd9a11b3c570eb28399215d2f44c2bb7062c82fcde5a33
```

# Advantages
**Security First**: AES-256-GCM ensures confidentiality, authentication, and integrity. SHA-256 hashing is widely recognized for secure file verification.

**Lightweight and Portable**: Minimal dependencies, runs on Linux and Windows.

**Professional Usability**: Simple CLI interface allows integration into scripts, automated workflows, and batch processing.

**Error-Resistant**: Detects incorrect passwords, corrupted files, and provides informative feedback to prevent data loss.

# Why Use This Tool

Data breaches, accidental leaks, and file tampering are everyday threats. `File Crypt CLI` empowers developers, students, and professionals to:

**Protect sensitive documents and projects**

**Safeguard credentials, databases, or research files**

**Verify integrity of files exchanged over untrusted networks**

**Integrate encryption into automated pipelines without heavy libraries**

It is perfect for coursework, research projects, and real-world applications where strong, authenticated encryption is needed.

# Licence

<a href="https://github.com/abdulatif-abdumannopov/file-crypt-cli">File Crypt CLI</a> © 2025 by <a href="https://github.com/abdulatif-abdumannopov">Abdumannopov Abdulatif</a> is licensed under <a href="https://github.com/abdulatif-abdumannopov/file-crypt-cli?tab=License-1-ov-file">NCL 1.0</a>
