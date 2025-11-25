# Qeltrix (.qltx)

**Content-Derived, Parallel, Streaming Obfuscation Container (PoC)**

Qeltrix is a Proof-of-Concept command-line utility for creating encrypted, content-derived, and efficiently compressed data containers. It leverages parallel processing, modern cryptography (ChaCha20-Poly1305), and a streaming architecture suitable for large files.

The `qeltrix-pypi` folder in this repository contains the PyPI package intended for upload. Due to technical issues, I'm currently unable to publish it to PyPI. The folder includes a detailed README.md with full documentation for the PyPI package, which currently only covers the V1 format.

**For more detailed documentation, please see qeltrix-pypi's README.md**

---

## Features (V1 Format - Implemented in qeltrix.py)

Qeltrix V1 containers offer a robust combination of performance and security features:

**Content-Derived Keying**: The encryption key is derived directly from the content of the file being packaged, eliminating the need to store or transfer a separate secret.

- **two_pass Mode (Default)**: The key is derived from the SHA256 hash of the entire compressed stream. This provides a stronger, content-dependent key but requires temporary disk space (for storing compressed blocks) and two passes over the data.

- **single_pass_firstN Mode**: The key is derived from the hash of the first N raw bytes of the input file. This allows for a fast, single-pass operation with bounded memory usage, ideal when speed is critical and the beginning of the file is sufficiently unique.

**Parallel Processing**: Uses `concurrent.futures.ProcessPoolExecutor` for parallel block compression/encryption, maximizing throughput on multi-core systems.

**Streaming & Disk-Backed**: Designed for large files, writing encrypted blocks in a streaming fashion and using temporary files for intermediate compressed data in two_pass mode.

**Cryptography**: Implements modern AEAD (Authenticated Encryption with Associated Data) using ChaCha20-Poly1305 via the cryptography library for strong security.

**Data Transformation**: Includes per-block LZ4 compression and a deterministic, content-seeded permutation step for additional obfuscation before encryption.

**Integrity**: Uses a global ciphertext SHA256 checksum and per-block Poly1305 tags to ensure the file has not been tampered with.

---

## Qeltrix V2 (qeltrix-2.py) Enhancements

The V2 format, implemented in the separate `qeltrix-2.py` script, is designed for high-performance retrieval and greater flexibility. It maintains full backward compatibility with V1 files.

### 1. New Core Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Parallel Unpacking** | The unpack and seek commands leverage ProcessPoolExecutor to decrypt, unpermute, and decompress multiple blocks simultaneously. | Dramatically faster data retrieval on multi-core systems. |
| **Seekability / Random Access** | The new seek command uses the block index to quickly locate, retrieve, and process only the necessary data blocks to fulfill a specific byte-range request. | Allows for fast reading of arbitrary file sections without decrypting the entire container. |
| **Zstandard (Zstd) Support** | Added `--compression zstd` option for packing. | Provides a robust alternative to LZ4, often yielding better compression ratios at moderate speed. |
| **V1 Backward Compatibility** | The tool automatically detects the file version (V1 or V2) and uses the corresponding Key Derivation Function (info string) and compression defaults (LZ4 for V1). | Ensures seamless migration and interoperability with older files. |
| **Format Version** | Internal format version bumped to 2. | Clearly identifies files that support V2-specific features (like Zstd). |

### 2. Dependencies for V2

The V2 script introduces a new dependency for Zstandard compression support:

```bash
pip install lz4 cryptography zstandard
```

### 3. Usage & New CLI Options

V2 introduces the new `seek` command and additional options for `pack` and `unpack`.

| Command | Usage / New Parameter | Description |
|---------|----------------------|-------------|
| `pack` | `--compression {lz4, zstd}` | Specifies the per-block compression algorithm. Default: `lz4`. |
| `unpack` | `--workers N` | Specifies the number of processes to use for parallel decryption. Default: CPU count. |
| **New!** `seek` | `infile offset length` | Reads `length` bytes starting at `offset` from the virtual uncompressed stream. |
| `seek` | `--output FILE` | Optional file path to write the output data to (otherwise prints to stdout). |
| `seek` | `--workers N` | Specifies the number of processes for parallel decompression during seek. |

**Example (Packing with Zstd in V2):**

```bash
python3 qeltrix-2.py pack my_report.pdf compressed.qltx --compression zstd
```

**Example (Seeking in V2):**

```bash
# Read 4KB starting at 10MB into stdout
python3 qeltrix-2.py seek recovered_file.qltx 10485760 4096
```

---

## Installation

Qeltrix is written in Python 3 and requires several external dependencies.

### Prerequisites

You must have Python 3.8+ installed.

### Dependencies

Install the required Python packages using pip (note that the V2 tool will require zstd support):

```bash
pip install lz4 cryptography zstandard
```

---

## Usage

The `qeltrix.py` (V1) and `qeltrix-2.py` (V2) scripts use subcommands: `pack` to create a container and `unpack` to extract its contents. (See sections above for detailed usage.)

### 1. Packing a File

Use the `pack` subcommand to create a `.qltx` container.

```bash
python3 qeltrix.py pack <INFILE> <OUTFILE.qltx> [OPTIONS]
```

**Example (Default two_pass mode):**

This is the recommended mode for maximum key entropy, as the key is derived from the entire content.

```bash
python3 qeltrix.py pack my_large_file.dat output.qltx
```

#### Pack Options

| Option | Default | Description |
|--------|---------|-------------|
| `--block-size` | 1048576 (1MB) | Size of raw data chunks to process in each block. |
| `--mode` | `two_pass` | Key derivation mode: `two_pass` (full content hash) or `single_pass_firstN`. |
| `--head-bytes` | 1048576 (1MB) | For `single_pass_firstN` mode, the number of raw bytes used for key derivation. |
| `--workers` | (CPU Count) | Number of worker processes to use for parallel compression/encryption. |
| `--no-permute` | | Disable the deterministic permutation layer. |
| `--tempdir` | (System default) | Specify a directory for temporary files (only used in `two_pass` mode). |

**Example (single_pass_firstN):**

To maximize speed by deriving the key from the first 4MB of the input file:

```bash
python3 qeltrix.py pack large_video.mp4 fast_pack.qltx --mode single_pass_firstN --head-bytes 4194304
```

### 2. Unpacking a File

Use the `unpack` subcommand to decrypt and decompress a `.qltx` container. The key is automatically re-derived from the file's metadata and content.

```bash
python3 qeltrix.py unpack <INFILE.qltx> <OUTFILE> [OPTIONS]
```

**Example:**

```bash
python3 qeltrix.py unpack output.qltx recovered_file.dat
```

#### Unpack Options

| Option | Default | Description |
|--------|---------|-------------|
| `--no-verify` | | Skip the global ciphertext SHA256 verification (faster, but less secure). |

---

## File Format Overview

The Qeltrix container (`.qltx`) structure is designed for stream processing and looks like this:

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `QLTX` identifier. |
| Version | 1 byte | Format version (1 or 2). |
| Reserved | 3 bytes | Reserved for future use. |
| Meta Length | 4 bytes (BE uint32) | Length of the JSON metadata block. |
| Metadata JSON | Variable | JSON block containing salt, block_size, mode_tag, compression type, and key-derivation hash (h or head_hash). Used as AEAD associated data. |
| Ciphertext Blocks | Variable | Sequentially encrypted data blocks. |
| Delimiter | 9 bytes | `QDELIMITERQ` string for reliable footer lookup. |
| Footer JSON | Variable | JSON containing the block index (offset, nonce, length) and the `global_ciphertext_sha256`. |
| Footer Length | 4 bytes (BE uint32) | Length of the Footer JSON block. |

---

## Future Possibilities

As a Proof-of-Concept, Qeltrix demonstrates several core ideas. Future versions and development could focus on:

**Key Derivation Flexibility**: Introducing more modes for key derivation, such as combining multiple file sections or using external secret material.

**Metadata Flexibility**: Enhancing the metadata block to support file system information, permissions, or custom user tags.

**Asymmetric Key Transport**: Integrate an asymmetric encryption layer (e.g., RSA or ECC) to secure the symmetric key used for bulk data encryption. Since the core ChaCha20-Poly1305 is fast, the asymmetric overhead is applied only to the small symmetric key and metadata (includes footer also), not the large data blocks, enabling a Public/Private Key Architecture for secure key exchange.

---

## Licensing

This project uses dual licensing:

### Code Implementation

The Python implementation (`qeltrix.py`) and associated code are licensed under **GPLv3** (GNU General Public License version 3). You are free to use, modify, and distribute the code under the terms of the GPL.

### Original Concept

The underlying concept, cryptographic approach, and file format design of Qeltrix are licensed under **CC BY-SA 4.0** (Creative Commons Attribution-ShareAlike 4.0 International). This means:

- You must give appropriate credit to the original author
- You may adapt and build upon the concept
- If you remix, transform, or build upon the concept, you must distribute your contributions under the same CC BY-SA 4.0 license
- You may use the concept for any purpose, including commercially

---

**Qeltrix (.qltx) Concept & Implementation**  
**Copyright © 2025 HejHdiss (Muhammed Shafin P)**

**Code:** GPLv3 | **Concept:** CC BY-SA 4.0 International
