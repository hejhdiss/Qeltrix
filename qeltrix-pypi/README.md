# Qeltrix (.qltx)

**Content-Derived, Parallel, Streaming Obfuscation Container (PoC)**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Concept License: CC BY-SA 4.0](https://img.shields.io/badge/Concept%20License-CC%20BY--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-sa/4.0/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Qeltrix is a Proof-of-Concept command-line utility for creating encrypted, content-derived, and efficiently compressed data containers. It leverages parallel processing, modern cryptography (ChaCha20-Poly1305), and a streaming architecture suitable for large files.

> **Note:** This is a **CLI tool/script**, not an importable Python module. It is designed to be used directly from the command line for packing and unpacking files.

---

## Features

Qeltrix containers offer a robust combination of performance and security features:

**Content-Derived Keying:** The encryption key is derived directly from the content of the file being packaged, eliminating the need to store or transfer a separate secret.

- **two_pass Mode (Default):** The key is derived from the SHA256 hash of the entire compressed stream. This provides a stronger, content-dependent key but requires temporary disk space (for storing compressed blocks) and two passes over the data.

- **single_pass_firstN Mode:** The key is derived from the hash of the first N raw bytes of the input file. This allows for a fast, single-pass operation with bounded memory usage, ideal when speed is critical and the beginning of the file is sufficiently unique.

**Parallel Processing:** Uses `concurrent.futures.ProcessPoolExecutor` for parallel block compression/encryption, maximizing throughput on multi-core systems.

**Streaming & Disk-Backed:** Designed for large files, writing encrypted blocks in a streaming fashion and using temporary files for intermediate compressed data in two_pass mode.

**Cryptography:** Implements modern AEAD (Authenticated Encryption with Associated Data) using ChaCha20-Poly1305 via the cryptography library for strong security.

**Data Transformation:** Includes per-block LZ4 compression and a deterministic, content-seeded permutation step for additional obfuscation before encryption.

**Integrity:** Uses a global ciphertext SHA256 checksum and per-block Poly1305 tags to ensure the file has not been tampered with.

---

## Installation

Qeltrix is written in Python 3 and requires several external dependencies.

### Prerequisites

You must have Python 3.8+ installed.

### Quick Install

```bash
# Clone the repository
git clone https://github.com/hejhdiss/Qeltrix.git
cd Qeltrix

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/macOS)
chmod +x qeltrix.py

# Optional: Install system-wide
sudo cp qeltrix.py /usr/local/bin/qeltrix
```
OR

```bash 
pip install qeltrix-pypi-package-name

```


### Dependencies

Install the required Python packages using pip:

```bash
pip install lz4 cryptography
```

Or use the requirements file:

```bash
pip install -r requirements.txt
```
OR 

```
if installed with the pip ,it will install dependencies also.
```

---

## Usage

The `qeltrix.py` script uses subcommands: `pack` to create a container and `unpack` to extract its contents.

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

OR 

```
if installed using pip and  the python scripts folder is in system path, can use qeltrix-pypi-package-name [COMMANDS]
```

#### Pack Options

| Option | Default | Description |
|--------|---------|-------------|
| `--block-size` | 1048576 (1MB) | Size of raw data chunks to process in each block. |
| `--mode` | two_pass | Key derivation mode: `two_pass` (full content hash) or `single_pass_firstN`. |
| `--head-bytes` | 1048576 (1MB) | For `single_pass_firstN` mode, the number of raw bytes used for key derivation. |
| `--workers` | (CPU Count) | Number of worker processes to use for parallel compression. |
| `--no-permute` | | Disable the deterministic permutation layer. |
| `--tempdir` | (System default) | Specify a directory for temporary files (only used in two_pass mode). |

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
| Version | 1 byte | Format version (1). |
| Reserved | 3 bytes | Reserved for future use. |
| Meta Length | 4 bytes (BE uint32) | Length of the JSON metadata block. |
| Metadata JSON | Variable | JSON block containing `salt`, `block_size`, `mode_tag`, and either `h` (two-pass) or `head_hash` (single-pass). Used as AEAD associated data. |
| Ciphertext Blocks | Variable | Sequentially encrypted data blocks. |
| Delimiter | 9 bytes | `QDELIMITERQ` string for reliable footer lookup. |
| Footer JSON | Variable | JSON containing the block index (offset, nonce, length) and the `global_ciphertext_sha256`. |
| Footer Length | 4 bytes (BE uint32) | Length of the Footer JSON block. |

---

## Future Possibilities

As a Proof-of-Concept, Qeltrix demonstrates several core ideas. There is **no guarantee of future updates or development** by the original author. This is a **for-the-community, by-the-community** project. The following are potential enhancements that anyone in the community can explore and implement:

**Parallel Decoding:** Implementing multi-threaded or multi-process parallelization for the unpacking/decryption phase to significantly speed up data retrieval.

**Seekability:** Adding random-access capabilities to seek to specific blocks without processing the entire file, enabling faster partial extraction and streaming playback.

**Alternative Compression:** Integration of other compression algorithms (e.g., Zstd, Brotli, LZMA) for comparison and optimal container size/speed trade-offs.

**Key Derivation Flexibility:** Introducing more modes for key derivation, such as combining multiple file sections or using external secret material.

**Metadata Flexibility:** Enhancing the metadata block to support file system information, permissions, or custom user tags.

**Incremental Updates:** Supporting modification of individual blocks without reprocessing the entire file.

**Deduplication:** Block-level deduplication to identify and eliminate redundant data.

**Error Correction:** Adding Reed-Solomon or other error correction codes for resilience against storage corruption.

**Multi-file Containers:** Extending the format to package multiple files with an internal directory structure.

**Additional Enhancements:** Encryption algorithm variants, sparse file support, digital signatures, block size auto-tuning, streaming encryption for unknown-size data, and more.

Feel free to fork, extend, and build upon this concept!

---

## Security Considerations

As a PoC, Qeltrix demonstrates concepts but should **not be used for production security-critical applications** without thorough review and hardening. Some considerations:

- Content-derived keys mean identical files produce identical containers (deterministic encryption)
- The security depends entirely on content uniqueness and entropy
- Susceptible to "confirmation of file attack" where someone with an identical file can confirm you also possess it (this is generally not a concern for most use cases, but matters in specific threat models)
- No password recovery mechanism exists by design
- The permutation layer provides obfuscation but not cryptographic strength

For sensitive applications requiring plausible deniability, consider using traditional encryption with unique passwords or keys.

---

## Licensing

This project uses dual licensing to ensure both the code and the underlying concept remain open and accessible:

### Code Implementation
The Python implementation (`qeltrix.py`) and associated code are licensed under **GPLv3** (GNU General Public License version 3). You are free to use, modify, and distribute the code under the terms of the GPL.

### Original Concept
The underlying concept, cryptographic approach, and file format design of Qeltrix are licensed under **CC BY-SA 4.0** (Creative Commons Attribution-ShareAlike 4.0 International). This means:
- You must give appropriate credit to the original author
- You may adapt and build upon the concept
- If you remix, transform, or build upon the concept, you must distribute your contributions under the same CC BY-SA 4.0 license
- You may use the concept for any purpose, including commercially

**Full License Texts:**
- [GPLv3 License](https://www.gnu.org/licenses/gpl-3.0.en.html)
- [CC BY-SA 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/)

---

## Contributing

This is an open, community-driven project. The original author has introduced the concept, and its evolution is now in the hands of the community. Contributions, forks, improvements, and derivative works are encouraged!

Whether you want to:
- Fix bugs or improve performance
- Add new features (parallel decryption, seekability, alternative compression)
- Create implementations in other languages
- Write better documentation
- Extend the concept in new directions

Your contributions are welcome! Please feel free to:
- Open issues for bugs or feature requests
- Submit pull requests with improvements
- Fork the project for your own experiments
- Share your derivative works with the community

Visit the repository at [github.com/hejhdiss/Qeltrix](https://github.com/hejhdiss/Qeltrix) to get started.

---

## Project Status

**This is a Proof of Concept.** There is no guarantee of ongoing development or updates by the original author. The project is intentionally designed as a foundation for community exploration and extension. Whether Qeltrix evolves into something larger depends entirely on community interest and contributions.

---

## Author & Copyright

**Qeltrix (.qltx) Concept & Implementation**  
Copyright © 2025 HejHdiss (Muhammed Shafin P)  

Code Implementation: Licensed under GPLv3  
Original Concept: Licensed under CC BY-SA 4.0 International

**Contact:** [GitHub Profile](https://github.com/hejhdiss)  
**Repository:** [github.com/hejhdiss/Qeltrix](https://github.com/hejhdiss/Qeltrix)


