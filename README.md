# Qeltrix (.qltx)

**Content-Derived, Parallel, Streaming Obfuscation Container (PoC)**

Qeltrix is a Proof-of-Concept command-line utility for creating encrypted, content-derived, and efficiently compressed data containers. It leverages parallel processing, modern cryptography (ChaCha20-Poly1305), and a streaming architecture suitable for large files.

The `qeltrix-pypi` folder in this repository contains the PyPI package intended for upload. Due to technical issues, I'm currently unable to publish it to PyPI. The folder includes a detailed README.md with full documentation for the PyPI package, which currently only covers the V1 format.

For more detailed documentation, please see `qeltrix-pypi`'s README.md

---

## Community & Project Status

This project is a personal **Proof-of-Concept (PoC)**, built by the community, for the community. As a PoC, it currently has significant limitations. Many complex and advanced **design plans were ultimately dropped** across all versions.

Specific examples of dropped features include:
* **V5 Advanced VFS:** Features like **parallel and serial mixing** of blocking and non-blocking file combinations within the Virtual File System (VFS), and other complex support structures, were planned but not implemented.
* **Cross-Version Enhancements:** Certain multi-parallel and blocking VFS operations that would improve throughput were stopped or scaled back in various versions.

These and many other planned features (including in V1, V2, V3, and V4) were abandoned due to the inherent **limitations of my knowledge** as the primary developer and the constraints of managing the project solo as a PoC.

We believe Qeltrix's foundational architecture is robust, but it requires collaborative effort to achieve its full potential. We encourage the community to **take over** this project, help improve the codebase, address its current limitations, and implement the features necessary to build a better, more secure product.

**Your contribution matters!** If you are unable to contribute code, we greatly value **feedback**, bug reports, and suggestions for improvement.

---

# Universal Dispatcher: qltx.py (Recommended Entry) 

The primary entry point for all operations is the universal dispatcher script, `qltx.py`.

It automatically detects the necessary Qeltrix format version (V1, V2, V3, or V4) based on the command and arguments for `pack`, or by reading the file header for `unpack` and `seek`. It then executes the correct versioned backend script (e.g., `qeltrix-4.py`) seamlessly.

We highly recommend using `qltx.py` for all operations to ensure backward compatibility and automatic feature selection. This provides an "all-in-one" experience.

The `qltx.py` dispatcher now requires an explicit version flag (`-v`) for the `pack` command to prevent accidental version selection, but retains automatic version detection for decoding commands (`unpack`, `seek`).

## Dispatcher Usage

| Command | Usage | Description |
|---------|-------|-------------|
| pack | `python qltx.py -v <version_num> pack <INFILE> <OUTFILE.qltx> [args...]` | Mandatory explicit version selection is required for packing (e.g., `-v 4` for V4). |
| unpack | `python qltx.py unpack <qltx_file> <OUTFILE> [args...]` | Auto-detects version from the file header (V1-V4 supported). |
| seek | `python qltx.py seek <qltx_file> offset length [args...]` | Auto-detects version from the file header (V1-V4 supported). |


### For V5 (Folder Archiving) Usage

**V5 is the first version to support folder archiving.** Its arguments are specific to the Virtual File System (VFS) model and differ from V1-V4 single-file operations.

| Command | Usage | Description |
|:---|:---|:---|
| `pack` | `python qltx.py pack --input-folder <PATH> --output-file <ARCHIVE.q5> -v 5,[args...]` | **Mandatory explicit version** (`-v 5`). Archives an entire **folder** into a V5/V5A file. Use `--public-key` for V5A mode. |
| `unpack` | `python qltx.py unpack --input-file <ARCHIVE.q5> --output-folder <PATH> [args...]` | Unpacks the V5/V5A archive to a designated **output folder**. |
| `seek` | `python qltx.py seek --input-file <ARCHIVE.q5> --vfs-path <FILE_PATH> --offset <N> --length <L> [args...]` | **VFS Seek**: Reads a byte range from a specific file path **inside** the archive. Requires the `--vfs-path` argument. |

> **Important Note on V5 Data Model:**
> Versions **V1 through V4** are designed to operate on a **single input file**, where the entire file content is treated as one stream or a series of identical blocks. **V5** introduces a **Virtual File System (VFS)** model, allowing it to package an entire **folder** into a single container. Consequently, V5 uses distinct command-line arguments like `--input-folder` and `--vfs-path` that are not compatible with the older, single-file versions.

## Qeltrix V5 (qeltrix-5.py) Enhancements

The V5 format, implemented in the separate `qeltrix-5.py` script, transforms Qeltrix into a **Folder Archiver with VFS Seek** and introduces optional asymmetric encryption for metadata.

### 1. New Core Features

| Feature | Description | Benefit |
|---------|-------------|---------|
| **Folder Archiver** | V5 packages an entire directory, creating a Virtual File System (VFS) metadata block that maps relative paths, original sizes, and content hashes to data blocks. | Allows for archiving and retrieving multiple files within a single container. |
| **Optional Asymmetric Metadata Encryption** | The encryption of the VFS metadata block is now optional, creating two modes: | Increases flexibility and security. |
| **V5A Mode (Asymmetric)** | If `--public-key` is supplied during `pack`, the Metadata Encryption Key (MEK) is **RSA-encrypted** using the public key. This requires the corresponding `--private-key` for `unpack` or `seek`. | Enables secure, recipient-only sharing of archive contents. |
| **V5 Mode (Unencrypted)** | If `--public-key` is **omitted** during `pack`, the VFS metadata is stored as **unencrypted JSON** alongside the data blocks. | Allows for rapid unpacking and seeking without requiring a private key (though the content blocks remain encrypted by the master key). |
| **Backward Block Compatibility** | V5 is designed to pack and unpack individual file blocks using the **V2 (ChaCha20-Poly1305)** or **V4 (AES256-GCM)** format, specified via the `-v` config string (e.g., `-v 4,--compression=zstd`). | Leverages proven and tested block encryption methods while providing new VFS features. |
| **Parallel Processing** | Utilizes Python's ProcessPoolExecutor for concurrent, CPU-intensive operations (encryption, decryption, compression).


pack/unpack: Uses default workers (typically os.cpu_count()) for high throughput.

seek: Uses max_workers=1 to run the single block decryption/decompression in a separate, isolated process.

(Note: As a POC, it currently lacks an explicit --workers command-line argument, defaulting to the system's core count or 1 if os.cpu_count() is unavailable.Since this is a community project, contributions to add an explicit worker configuration are welcome!) | Dramatically improves performance for high-volume operations and isolates single-block operations like seek. |
| **VFS Seek (Virtual File System Seek)** | Allows direct retrieval of a byte range (using --offset and --length) from a single file inside the archive, without needing to decrypt or decompress the entire archive or even the entire file block. | Enables instant access to small parts of large archived files (e.g., retrieving a config file header or log file segment) without full extraction, saving significant time and resources. |
| **Format Version** | Internal format version bumped to **5**. | Clearly identifies files that support the V5 VFS and optional asymmetric metadata features. |

### 2. Dependencies for V5

V5 requires the same dependencies as previous versions:

```bash
pip install lz4 cryptography zstandard
```
##  Qeltrix V5 Command-Line Usage

The Qeltrix V5.5(internal version) three main commands: `pack` (archiving), `unpack` (extraction), and `seek` (Virtual File System (VFS) seek).

---

### Global Options

These options apply to all commands:

| Option | Description | Default |
|:---|:---|:---|
| `cmd` | **Command**: Must be `pack`, `unpack`, or `seek`. | None (Required) |
| `--key <KEY>` | **Master key** (password) for block content encryption/decryption. | `""` (empty string) |
| `--private-key <PATH>` | **RSA Private Key** path. **REQUIRED** for `unpack` or `seek` of V5A (Asymmetrically Encrypted Metadata) archives. | `None` |
| `--public-key <PATH>` | **RSA Public Key** path. If supplied during `pack`, the archive uses **V5A mode** (Asymmetric Metadata Encryption). | `None` |

---

### `pack` Command Arguments (Archiving)

Creates a new V5/V5A archive from a folder.

| Option | Description | Default |
|:---|:---|:---|
| `--input-folder <PATH>` | **Input folder** path to archive. | None (Required) |
| `--output-file <PATH>` | **Output V5 archive** file path (e.g., `archive.q5`). | None (Required) |
| `-v, --v-config <CONFIG>` | **V2/V4 Block Config**: Defines encryption, compression, and key derivation mode for data blocks. | `4,--compression=lz4,--permute,--mode=two_pass` |

> ##### V-Config Format and Parameters
>
> The configuration string is: `VERSION,[--compression=<TYPE>|--permute|--mode=<TYPE>]`
>
> | Parameter | V-Config Syntax | Description |
|:---|:---|:---|
| **Version** | `2` or `4` | **2**: Uses ChaCha20-Poly1305. **4**: Uses AES-256-GCM. |
| **Compression** | `--compression=<TYPE>` | Type: `lz4`, `zstd` (if available), or `none`. |
| **Permutation** | `--permute` | Enables the content-seeded deterministic XOR byte permutation layer. |
| **KDF Mode** | `--mode=<TYPE>` | **`two_pass`**: Hashes the entire file (More secure). **`single_pass_firstn`**: Hashes only the first 1024 bytes (Faster). |

---

### `unpack` Command Arguments (Extraction)

Extracts the contents of a V5/V5A archive.

| Option | Description | Default |
|:---|:---|:---|
| `--input-file <PATH>` | **Input V5 archive** file path. | None (Required) |
| `--output-folder <PATH>` | **Output folder** path to extract files into. | None (Required) |

---

### `seek` Command Arguments (VFS Seeking)

Retrieves a specific byte range from a single file inside the archive.

| Option | Description | Default |
|:---|:---|:---|
| `--input-file <PATH>` | **Input V5 archive** file path. | None (Required) |
| `--vfs-path <PATH>` | The **relative path** of the file inside the archive to seek into. | None (Required) |
| `--offset <BYTES>` | **Start offset** in bytes within the VFS file to begin reading. | `0` |
| `--length <BYTES>` | **Number of bytes** to read from the offset. | `1024` |
| `--output <PATH>` | Optional file path to write the extracted seek data. (Prints hex preview if omitted). | `None` |

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
|Enforced two_pass Architecture | Restricted to the two_pass architecture for key derivation. The single_pass_firstN mode is unsupported because it decreases security (as it relies on hashing only the first N bytes) and is complex to implement in this PoC. Future contributors can add the single_pass_firstN mode in a subsequent version. | Ensures highest key derivation security for V3. |
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

## Qeltrix V4 (qeltrix-4.py) Enhancements 

The V4 format, implemented in the new qeltrix-4.py script, introduces a major cryptographic upgrade, focusing solely on high-standard AEAD.

| Feature | Description | Benefit |
|---------|-------------|---------|
| Cryptographic Standard | Switched from ChaCha20-Poly1305 to AES256-GCM (Advanced Encryption Standard with Galois/Counter Mode) | Provides a standardized, widely-vetted, and hardware-accelerated AEAD cipher for bulk data encryption |
| Breaks Backward Compatibility | The qeltrix-4.py script only supports V4 files | Ensures a clean, modern cryptographic foundation without maintaining legacy ciphers in the core script |
| Retained Features | Maintains all V2 features: parallel decryption, seekability, Zstd/LZ4 compression, and both two_pass/single_pass_firstN key derivation modes | Offers V4 security with V2 performance and flexibility |
| Key Info String | Uses a new, V4-specific key derivation info string for HKDF (KEY_INFO_V4) | Prevents key re-use across different format versions |
 
### Commands

The `qeltrix-4.py` script supports three main commands: `pack`, `unpack`, and `seek`.

#### 1. pack - Creating a V4 Container

This command creates a new Qeltrix V4 container. It uses the file's content to derive the AES256 key, ensuring the key is self-contained within the data.

**Basic Usage:**

```bash
python3 qeltrix-4.py pack <INFILE> <OUTFILE.qltx> [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--block-size <BYTES>` | The size of each data block processed in parallel. | `1048576` (1MB) |
| `--compression <TYPE>` | Compression algorithm to use: `lz4`, `zstd`, or `none`. | `lz4` |
| `--mode <TYPE>` | Key derivation mode: `two_pass` (more secure) or `single_pass_firstN` (faster). | `two_pass` |
| `--head-bytes <BYTES>` | Used with `single_pass_firstN` mode to specify the amount of data to hash. | `1048576` (1MB) |
| `--no-permute` | Disable the content-seeded byte permutation layer. | Permutation is enabled |
| `--workers <N>` | Number of parallel worker processes to use. | System CPU count |
| `--tempdir <PATH>` | Path for temporary block storage during the packing process. | System temporary directory |

**Example:**

```bash
# Uses AES256-GCM, Zstd compression, and two_pass key derivation
python3 qeltrix-4.py pack large_backup.iso backup_v4.qltx --compression zstd --block-size 4194304
```

#### 2. unpack - Decrypting and Extracting

This command reads the V4 container, decrypts and decompresses the contents, and writes the original data to the specified output file or standard output.

**Basic Usage:**

```bash
python3 qeltrix-4.py unpack <INFILE.qltx> <OUTFILE> [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--no-verify` | Skip the global SHA256 integrity check (faster, less safe). | Verification is enabled |
| `--workers <N>` | Number of parallel worker processes for block decryption/decompression. | System CPU count |

**Example:**

```bash
# Unpacks the file, leveraging multiple cores for parallel processing
python3 qeltrix-4.py unpack backup_v4.qltx restored_file.iso --workers 8
```

#### 3. seek - Random Access Retrieval (V2+ Feature)

This command allows for fast, random access to a specific byte range within the container without needing to decrypt the entire file. It is ideal for quickly reading file headers or extracting small sections from large archives.

**Basic Usage:**

```bash
python3 qeltrix-4.py seek <INFILE.qltx> <OFFSET> <LENGTH> [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `<OFFSET>` | The starting byte position (zero-indexed) in the original unencrypted file. | (Required) |
| `<LENGTH>` | The number of bytes to retrieve starting from the offset. | (Required) |
| `--output <FILE>` | Optional file path to write the output data to. If omitted, output goes to stdout. | stdout |
| `--workers <N>` | Number of parallel worker processes for block decryption/decompression. | System CPU count |

**Example: Reading a 4KB header at 10MB into a file**

```bash
# Reads 4096 bytes (4KB) starting at byte 10485760 (10MB)
python3 qeltrix-4.py seek data_archive.qltx 10485760 4096 --output header_extract.bin
```

### Dependencies for v4

Install the required Python packages using pip:

```bash
pip install lz4 cryptography zstandard
```

## Installation

Qeltrix is written in Python 3 and requires several external dependencies.

### Prerequisites

You must have Python 3.8+ installed.

### Dependencies

Install the required Python packages using pip:

```bash
pip install lz4 cryptography zstandard
```


#### Pack Options (All Versions - except V5)
***

**Note on V5 (qeltrix-5.py):** The V5 Archiver introduces a fundamental shift to folder archiving with optional asymmetric metadata encryption.it also adds several unique, mandatory arguments and features. **Refer to the specific V5 Pack Options table.**

***


| Option | Version | Default | Description |
|--------|---------|---------|-------------|
| `--block-size` | V1+ | 1048576 (1MB) | Size of raw data chunks to process in each block. |
| `--mode` | V1+ | two_pass | Key derivation mode: `two_pass` (full content hash) or `single_pass_firstN`. Note: The V3 script (qeltrix-3.py) only supports two_pass. |
| `--head-bytes` | V1+ | 1048576 (1MB) | For `single_pass_firstN` mode, the number of raw bytes used for key derivation.Note: Not applicable in V3. |
| `--workers` | V1+ | (CPU Count) | Number of worker processes to use for parallel compression/encryption. |
| `--no-permute` | V1+ | | Disable the deterministic permutation layer. |
| `--tempdir` | V1+ | (System default) | Specify a directory for temporary files (only used in `two_pass` mode). |
| `--compression` | V2+ | lz4 | Specifies the per-block compression algorithm: `{lz4, zstd}`. |
| `--algo` | V3+ | chacha20 | Specifies the bulk encryption algorithm: `{chacha20, aes256}`.Note: Not applicable in V4. |
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

The `seek` command is also routed by `qltx.py` and supports V2, V3 and V4 iles.

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

Note on Test Scripts: The comprehensive dispatcher test script, test-qltx.py, has been removed.

To run these tests, ensure all dependencies are installed and execute the scripts directly. The tests create a temporary directory (`qeltrix_..._test_data`) for their operations and perform clean-up afterwards.

| Script Name | Target Script | Coverage |
|-------------|--------------|----------|
| `test.py` | `qeltrix.py` (V1) | Basic V1 functionality, including `two_pass` and `single_pass_firstN` key derivation modes. |
| `test-2.py` | `qeltrix-2.py` (V2) | V2-specific features: Zstandard (Zstd) compression, parallel unpacking, and random access (seek). |
| `test-3.py` | `qeltrix-3.py` (V3) | V3-specific features: Symmetric V3 pack/unpack, Asymmetric (V3-A) pack/unpack/seek, signing/verification, and AES-GCM encryption. |
| `test-4.py` | `qeltrix-4.py` (V4) | V4-specific features: AES256-GCM, parallel unpack, and seek. |
| `test-5.py` (NEW) | `qeltrix-4.py` (V5) | 

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

The Python implementation (`qeltrix.py`, `qeltrix-2.py`, `qeltrix-3.py`,`qeltrix-4.py`, `qeltrix-5.py` and `qltx.py` dispatcher) and associated code are licensed under **GPLv3** (GNU General Public License version 3). You are free to use, modify, and distribute the code under the terms of the GPL.

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
