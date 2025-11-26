# Qeltrix (.qltx)

**Content-Derived, Parallel, Streaming Obfuscation Container (PoC)**

Qeltrix is a Proof-of-Concept command-line utility for creating encrypted, content-derived, and efficiently compressed data containers. It leverages parallel processing, modern cryptography (ChaCha20-Poly1305), and a streaming architecture suitable for large files.

The `qeltrix-pypi` folder in this repository contains the PyPI package intended for upload. Due to technical issues, I'm currently unable to publish it to PyPI. The folder includes a detailed README.md with full documentation for the PyPI package, which currently only covers the V1 format.

For more detailed documentation, please see `qeltrix-pypi`'s README.md

## Universal Dispatcher: qltx.py (Recommended Entry)

The primary entry point for all operations is the universal dispatcher script, `qltx.py`.

It automatically detects the necessary Qeltrix format version (V1, V2, or V3) based on the command and arguments for `pack`, or by reading the file header for `unpack` and `seek`. It then executes the correct versioned backend script (e.g., `qeltrix-3.py`) seamlessly.

We highly recommend using `qltx.py` for all operations to ensure backward compatibility and automatic feature selection. This provides an "all-in-one" experience.

You can, however, use the version-specific scripts (`qeltrix-1/2/3.py`) separately if you need direct control over a specific version's behavior for development, testing, or specialized use cases.

For detailed usage and examples using the dispatcher, please see the **Usage (Universal Dispatcher: qltx.py)** section further below.

## Features (V1 Format - Implemented in qeltrix.py)

Qeltrix V1 containers offer a robust combination of performance and security features:

- **Content-Derived Keying**: The encryption key is derived directly from the content of the file being packaged, eliminating the need to store or transfer a separate secret.
  - **two_pass Mode (Default)**: The key is derived from the SHA256 hash of the entire compressed stream. This provides a stronger, content-dependent key but requires temporary disk space (for storing compressed blocks) and two passes over the data.
  - **single_pass_firstN Mode**: The key is derived from the hash of the first N raw bytes of the input file. This allows for a fast, single-pass operation with bounded memory usage, ideal when speed is critical and the beginning of the file is sufficiently unique.

- **Parallel Processing**: Uses `concurrent.futures.ProcessPoolExecutor` for parallel block compression/encryption, maximizing throughput on multi-core systems.

- **Streaming & Disk-Backed**: Designed for large files, writing encrypted blocks in a streaming fashion and using temporary files for intermediate compressed data in `two_pass` mode.

- **Cryptography**: Implements modern AEAD (Authenticated Encryption with Associated Data) using ChaCha20-Poly1305 via the `cryptography` library for strong security.

- **Data Transformation**: Includes per-block LZ4 compression and a deterministic, content-seeded permutation step for additional obfuscation before encryption.

- **Integrity**: Uses a global ciphertext SHA256 checksum and per-block Poly1305 tags to ensure the file has not been tampered with.

### Usage Examples (Direct Script Call)

For direct access to the V1 features and behavior:

| Command | Example Usage | Description |
|---------|--------------|-------------|
| pack | `python3 qeltrix.py pack my_file.dat output.qltx` | Use the V1 script directly for default two-pass content keying. |
| pack | `python3 qeltrix.py pack video.mp4 fast.qltx --mode single_pass_firstN` | Use the fast, single-pass mode directly. |
| unpack | `python3 qeltrix.py unpack output.qltx recovered.dat` | Unpack a V1 container using the specific script. |

## Qeltrix V2 (qeltrix-2.py) Enhancements

The V2 format, implemented in the separate `qeltrix-2.py` script, is designed for high-performance retrieval and greater flexibility. It maintains full backward compatibility with V1 files.

### 1. New Core Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| Parallel Unpacking | The `unpack` and `seek` commands leverage `ProcessPoolExecutor` to decrypt, unpermute, and decompress multiple blocks simultaneously. | Dramatically faster data retrieval on multi-core systems. |
| Seekability / Random Access | The new `seek` command uses the block index to quickly locate, retrieve, and process only the necessary data blocks to fulfill a specific byte-range request. | Allows for fast reading of arbitrary file sections without decrypting the entire container. |
| Zstandard (Zstd) Support | Added `--compression zstd` option for packing. | Provides a robust alternative to LZ4, often yielding better compression ratios at moderate speed. |
| V1 Backward Compatibility | The tool automatically detects the file version (V1 or V2) and uses the corresponding Key Derivation Function (info string) and compression defaults (LZ4 for V1). | Ensures seamless migration and interoperability with older files. |
| Format Version | Internal format version bumped to 2. | Clearly identifies files that support V2-specific features (like Zstd). |

### 2. Dependencies for V2

The V2 script introduces a new dependency for Zstandard compression support:

```bash
pip install lz4 cryptography zstandard
```

### 3. Usage Examples (Direct Script Call)

For direct access to the V2 features:

| Command | Example Usage | Description |
|---------|--------------|-------------|
| pack | `python3 qeltrix-2.py pack file.dat out.qltx --compression zstd` | Use V2 features (like Zstd) by calling qeltrix-2.py directly. |
| seek | `python3 qeltrix-2.py seek file.qltx 10485760 4096` | Perform a random access seek (read 4KB at 10MB offset) using the specific V2 script. |

## Qeltrix V3 (qeltrix-3.py) Enhancements

The V3 format, implemented in the separate `qeltrix-3.py` script, introduces a major update focused on secure key transport via Asymmetric Cryptography and multi-algorithm support.

### 1. New Core Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| Asymmetric Key Transport | (V3-A mode) The Data Encryption Key (DEK) is generated randomly and then secured using RSA-OAEP with a recipient's public key. | Enables Public/Private Key Architecture for secure key exchange, allowing only the intended recipient to decrypt the data without sharing a content-derived key. |
| Optional Metadata Signing | The packager can sign the metadata block using their private key (RSA-PSS). | Provides sender authentication and verifiable integrity of the configuration (metadata). |
| Multi-Algorithm Support | Supports both ChaCha20-Poly1305 and AES256-GCM for bulk data encryption. | Offers flexibility for different security and performance requirements. |
| Strict V3 Format Support | The qeltrix-3.py script can only pack and unpack V3 format files. | Enforces clean separation of versions; use the qltx.py dispatcher for V1/V2 compatibility. |
| Format Version | Internal format version bumped to 3. | Clearly identifies files that support V3-specific features (like Asymmetric Key Transport). |

### 2. Dependencies for V3

V3 requires additional dependencies for RSA-OAEP, RSA-PSS, and AES256-GCM support:

```bash
pip install lz4 cryptography zstandard
```

### 3. Usage Examples (Direct Script Call)

For direct access to the V3 features:

| Command | Example Usage | Description |
|---------|--------------|-------------|
| pack | `python3 qeltrix-3.py pack secret.doc out.qltx --recipient-pub-key keys/recipient.pub` | Use V3-A asymmetric key transport by calling qeltrix-3.py directly. |
| pack | `python3 qeltrix-3.py pack data.zip out.qltx --algo aes256 --compression zstd` | Use AES256-GCM and Zstd compression by calling qeltrix-3.py directly. |
| unpack | `python3 qeltrix-3.py unpack out.qltx recovered.doc --decrypt-priv-key keys/my_private.key` | Unpack a V3-A file using the specific V3 script. |

## Installation

Qeltrix is written in Python 3 and requires several external dependencies.

### Prerequisites

You must have Python 3.8+ installed.

### Dependencies

Install the required Python packages using pip:

```bash
pip install lz4 cryptography zstandard
```

## Usage (Universal Dispatcher: qltx.py)

The recommended entry point for all operations is the universal dispatcher script, `qltx.py`. This script automatically detects the necessary Qeltrix format version (V1, V2, or V3) based on the command and arguments for `pack`, or by reading the file header for `unpack` and `seek`. It then executes the correct versioned backend script (e.g., `qeltrix-3.py`) seamlessly.

### 1. Packing a File (Version Auto-Detection)

Use the `pack` subcommand with all options you require. The dispatcher will choose the newest format version that supports the combination of arguments provided (e.g., using `--recipient-pub-key` will automatically select V3).

```bash
python3 qltx.py pack <INFILE> <OUTFILE.qltx> [OPTIONS]
```

#### Example 1 (V1/V2 Default - Content-Derived Keying):

This is the recommended default mode for maximum key entropy.

```bash
python3 qltx.py pack my_large_file.dat output.qltx
```

#### Example 2 (V3-A Feature - Asymmetric Key Transport):

This automatically selects the V3 backend script.

```bash
# Encrypts the DEK using 'recipient.pub' so only they can unpack it.
python3 qltx.py pack my_secret.doc encrypted_v3.qltx --recipient-pub-key keys/recipient.pub
```

#### Pack Options (All Versions)

| Option | Version | Default | Description |
|--------|---------|---------|-------------|
| `--block-size` | V1+ | 1048576 (1MB) | Size of raw data chunks to process in each block. |
| `--mode` | V1+ | two_pass | Key derivation mode: `two_pass` (full content hash) or `single_pass_firstN`. |
| `--head-bytes` | V1+ | 1048576 (1MB) | For `single_pass_firstN` mode, the number of raw bytes used for key derivation. |
| `--workers` | V1+ | (CPU Count) | Number of worker processes to use for parallel compression/encryption. |
| `--no-permute` | V1+ | | Disable the deterministic permutation layer. |
| `--tempdir` | V1+ | (System default) | Specify a directory for temporary files (only used in `two_pass` mode). |
| `--compression` | V2+ | lz4 | Specifies the per-block compression algorithm: `{lz4, zstd}`. |
| `--algo` | V3+ | chacha20 | Specifies the bulk encryption algorithm: `{chacha20, aes256}`. |
| `--recipient-pub-key` | V3 | | Enables V3-A mode. Path to the recipient's public key for DEK encryption. |
| `--signer-priv-key` | V3 | | Path to the sender's private key to sign the metadata block. |

### 2. Unpacking a File (Version Auto-Detection)

Use the `unpack` subcommand. The dispatcher reads the version from the `.qltx` file header and routes to the correct backend.

```bash
python3 qltx.py unpack <INFILE.qltx> <OUTFILE> [OPTIONS]
```

#### Example 1 (Unpacking a V1/V2 file):

```bash
python3 qltx.py unpack output.qltx recovered_file.dat
```

#### Example 2 (Unpacking a V3-A file):

```bash
# The dispatcher ensures the V3 backend is used to handle the private key.
python3 qltx.py unpack encrypted_v3.qltx recovered.doc --decrypt-priv-key keys/my_private.key
```

#### Unpack Options (All Versions)

| Option | Version | Default | Description |
|--------|---------|---------|-------------|
| `--no-verify` | V1+ | | Skip the global ciphertext SHA256 verification (faster, but less secure). |
| `--workers` | V2+ | (CPU Count) | Specifies the number of processes to use for parallel decryption. |
| `--decrypt-priv-key` | V3 | | Required for V3-A files. Path to the user's private key to decrypt the DEK. |
| `--verifier-pub-key` | V3 | | Optional. Path to the sender's public key to verify the metadata signature. |

### 3. Seeking / Random Access (V2+ Files Only)

The `seek` command is also routed by `qltx.py` and supports V2 and V3 files.

```bash
python3 qltx.py seek <INFILE> offset length [OPTIONS]
```

#### Example (Seeking in V2/V3):

```bash
# Read 4KB starting at 10MB into stdout
python3 qltx.py seek recovered_file.qltx 10485760 4096
```

#### Seek Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output FILE` | | Optional file path to write the output data to (otherwise prints to stdout). |
| `--workers N` | (CPU Count) | Specifies the number of processes for parallel decompression during seek. |
| `--decrypt-priv-key` | V3 | Required for V3-A files. Path to the user's private key to decrypt the DEK. |
| `--verifier-pub-key` | V3 | Optional. Path to the sender's public key to verify the metadata signature. |

## Test Suites and Verification

The repository includes a set of functional test scripts that verify the core features of each format version and the correct operation of the universal dispatcher.

To run these tests, ensure all dependencies are installed and execute the scripts directly. The tests create a temporary directory (`qeltrix_..._test_data`) for their operations and perform clean-up afterwards.

| Script Name | Target Script | Coverage |
|-------------|--------------|----------|
| `test.py` | `qeltrix.py` (V1) | Basic V1 functionality, including `two_pass` and `single_pass_firstN` key derivation modes. |
| `test-2.py` | `qeltrix-2.py` (V2) | V2-specific features: Zstandard (Zstd) compression, parallel unpacking, and random access (seek). |
| `test-3.py` | `qeltrix-3.py` (V3) | V3-specific features: Symmetric V3 pack/unpack, Asymmetric (V3-A) pack/unpack/seek, signing/verification, and AES-GCM encryption. |
| `test-qltx.py` | `qltx.py` (Dispatcher) | Comprehensive test of the `qltx.py` dispatcher to ensure it correctly selects the V1, V2, or V3 backend based on command-line arguments and file headers. |

## File Format Overview

The Qeltrix container (`.qltx`) structure is designed for stream processing and looks like this:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `QLTX` identifier. |
| Version | 1 byte | Format version (1, 2, or 3). |
| Reserved | 3 bytes | Reserved for future use. |
| Meta Length | 4 bytes (BE uint32) | Length of the JSON metadata block. |
| Metadata JSON | Variable | JSON block containing salt, block_size, mode_tag, compression type, algorithm, key-derivation hash/encrypted DEK, and signature. Used as AEAD associated data. |
| Ciphertext Blocks | Variable | Sequentially encrypted data blocks. |
| Delimiter | 9 bytes | `QDELIMITERQ` string for reliable footer lookup. |
| Footer JSON | Variable | JSON containing the block index (offset, nonce, length) and the `global_ciphertext_sha256`. |
| Footer Length | 4 bytes (BE uint32) | Length of the Footer JSON block. |

## Future Possibilities

As a Proof-of-Concept, Qeltrix demonstrates several core ideas. Future versions and development could focus on:

- **Key Derivation Flexibility**: Introducing more modes for key derivation, such as combining multiple file sections or using external secret material.
- **Metadata Flexibility**: Enhancing the metadata block to support file system information, permissions, or custom user tags.
- **Asymmetric Key Transport**: Integrate an asymmetric encryption layer (e.g., RSA or ECC) to secure the symmetric key used for bulk data encryption. Since the core ChaCha20-Poly1305 is fast, the asymmetric overhead is applied only to the small symmetric key and metadata (includes footer also), not the large data blocks, enabling a Public/Private Key Architecture for secure key exchange.

## Licensing and Project Status

### Disclaimer: Proof-of-Concept Status

Please note that Qeltrix is developed as a **Proof-of-Concept (PoC)**. While it incorporates robust cryptographic primitives, its development cadence is currently irregular.

### Community Project

Qeltrix is an open-source project driven by the community and for the community. Future updates, feature additions, and maintenance will depend on the interest and contributions of volunteers. We encourage users and developers to contribute code, documentation, and feature ideas.

### Code Implementation

The Python implementation (`qeltrix.py`, `qeltrix-2.py`, `qeltrix-3.py`, and `qltx.py` dispatcher) and associated code are licensed under **GPLv3** (GNU General Public License version 3). You are free to use, modify, and distribute the code under the terms of the GPL.

### Original Concept

The underlying concept, cryptographic approach, and file format design of Qeltrix are licensed under **CC BY-SA 4.0** (Creative Commons Attribution-ShareAlike 4.0 International). This means:

- You must give appropriate credit to the original author
- You may adapt and build upon the concept
- If you remix, transform, or build upon the concept, you must distribute your contributions under the same CC BY-SA 4.0 license
- You may use the concept for any purpose, including commercially

---

**Qeltrix (.qltx) Concept & Implementation**  
Copyright © 2025 HejHdiss (Muhammed Shafin P)  
Code: GPLv3 | Concept: CC BY-SA 4.0 International
