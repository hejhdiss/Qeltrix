#!/usr/bin/env python3
"""
Qeltrix V5.5 - development versioning , real version(V5) - Folder Archiver with VFS Seek, Key Modes, and Optional Asymmetric Metadata Encryption

VERSION 5.5 UPGRADE:
 - **FIXED:** Critical bug in content key derivation (HKDF info string mismatch) causing V4/V2 block decryption failure during unpack/seek.
 - **NEW FEATURE:** Metadata encryption is now optional.
    - If `--public-key` is supplied (V5A mode), metadata is RSA-encrypted (requires `--private-key` to unpack).
    - If `--public-key` is NOT supplied (V5 mode), metadata is stored as unencrypted JSON (keys not required).
 - V5 Header now includes a Metadata Mode flag.

NOTE: This requires 'cryptography', 'lz4', and 'zstandard'.

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.
"""

import os, io, json, struct, secrets, hashlib, argparse, time,sys
from typing import Optional, Dict, List, Tuple, Any
import lz4.frame

# Import zstandard conditionally
try:
    import zstandard as zstd
except ImportError:
    zstd = None
    print("Warning: zstandard library not found. Zstd compression/decompression is disabled.")

# --- CRYPTO IMPORTS ---
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
# Asymmetric Crypto for Metadata Encryption
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from concurrent.futures import ProcessPoolExecutor, as_completed # <--- ADD THIS LINE

# === V5.5 Format constants ===
V5_MAGIC = b"QLTX"        # Qeltrix global file magic
V5_VERSION = 5            # Current tool/format version
FOOTER_SIZE_BYTES = 8     # Size of the integer storing the footer offset (uint64_t)
METADATA_CIPHER = AESGCM # Cipher for encrypting the JSON metadata body (when used)
MEK_LEN = 32             # Metadata Encryption Key length (for AES-256)
MEK_NONCE_LEN = 12       # Nonce length for MEK cipher (AES-GCM)
MEK_TAG_LEN = 16         # Tag length for MEK cipher

# --- Metadata Mode Flags (1 byte written to header) ---
METADATA_MODE_NONE = 0      # Unencrypted JSON metadata (V5)
METADATA_MODE_ASYMMETRIC = 1 # RSA-OAEP protected MEK, AES-GCM encrypted JSON (V5A)


# === V2/V4 Format constants (Abstracted from original files) ===
BLOCK_CONFIGS = {
    2: { # V2 (ChaCha20-Poly1310)
        'CIPHER': ChaCha20Poly1305, 'NONCE_LEN': 12, 'TAG_LEN': 16,
        'SALT_SIZE': 16, 'KDF_ITERATIONS': 100000,
    },
    4: { # V4 (AES256-GCM)
        'CIPHER': AESGCM, 'NONCE_LEN': 12, 'TAG_LEN': 16,
        'SALT_SIZE': 16, 'KDF_ITERATIONS': 250000, 
    }
}
KDF_MODES = {
    'two_pass': 'TWO_PASS_HASH',
    'single_pass_firstn': 'SINGLE_PASS_HEAD',
}

# --- Shared Utility Functions ---

def load_rsa_key(filepath: str, is_private: bool) -> Any:
    """Loads a private or public RSA key from a file."""
    try:
        with open(filepath, "rb") as key_file:
            key_data = key_file.read()
        
        if is_private:
            return serialization.load_pem_private_key(key_data, password=None)
        else:
            return serialization.load_pem_public_key(key_data)
    except Exception as e:
        raise RuntimeError(f"Failed to load RSA key from {filepath}: {e}")

def get_derived_key(master_key: bytes, salt: bytes, version: int, mode: str, content_hash: bytes = b'') -> bytes:
    """Derives a strong key using HKDF based on the block version configuration and KDF mode.
    
    The content_hash is CRITICAL for the HKDF info string to ensure the derived key is unique 
    to the file content, which is required for modes like single_pass_firstn.
    """
    cfg = BLOCK_CONFIGS.get(version)
    if not cfg:
        raise ValueError(f"Unsupported block version: V{version}")
    
    info_prefix = f"qeltrix-v{version}-key-".encode('utf-8')
    mode_info = KDF_MODES.get(mode, 'UNKNOWN').encode('utf-8')
    
    # FIX: Ensure content_hash is always used here to match the derivation in the packer.
    hkdf_info = info_prefix + mode_info + content_hash
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=hkdf_info,
        backend=None # Use default backend
    )
    return hkdf.derive(master_key)

def get_mode_content_hash(data: bytes, mode: str) -> bytes:
    """Calculates the content hash based on the key derivation mode."""
    if mode == 'two_pass':
        # Hash the entire file content
        return hashlib.sha256(data).digest()
    elif mode == 'single_pass_firstn':
        # Hash only the first N bytes (N=1024 for example)
        head_bytes = data[:1024] 
        return hashlib.sha256(head_bytes).digest()
    return b''

def apply_permute(data: bytes, key: bytes, permute: bool) -> bytes:
    """Applies a deterministic XOR permutation using the key if 'permute' is True."""
    if not permute:
        return data
    
    permute_key = key[:32]
    key_stream = b''
    while len(key_stream) < len(data):
        key_stream += hashlib.sha256(permute_key + len(key_stream).to_bytes(4, 'big')).digest()
    
    key_stream = key_stream[:len(data)]
    return bytes(a ^ b for a, b in zip(data, key_stream))

def compress_data(data: bytes, compression: str) -> bytes:
    """Compresses data using lz4 or zstd."""
    if compression == 'none':
        return data
    elif compression == 'lz4':
        return lz4.frame.compress(data)
    elif compression == 'zstd' and zstd:
        cctx = zstd.ZstdCompressor(level=3)
        return cctx.compress(data)
    else:
        raise ValueError(f"Unsupported or unavailable compression method: {compression}")

def decompress_data(data: bytes, compression: str) -> bytes:
    """Decompresses data using lz4 or zstd."""
    if compression == 'none':
        return data
    elif compression == 'lz4':
        return lz4.frame.decompress(data)
    elif compression == 'zstd' and zstd:
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data)
    else:
        raise ValueError(f"Unsupported or unavailable decompression method: {compression}")

def parse_v_config(config_str: str) -> Tuple[int, Dict[str, Any]]:
    """Parses the -v configuration string into version and parameters."""
    parts = config_str.split(',')
    
    try:
        version = int(parts[0])
    except ValueError:
        raise ValueError(f"Invalid version number in config string: {parts[0]}")

    if version not in BLOCK_CONFIGS:
        raise ValueError(f"Unsupported Qeltrix Block Version: V{version}. Supported versions: {list(BLOCK_CONFIGS.keys())}")
        
    params = {
        'compression': 'none',
        'permute': False,
        'mode': 'two_pass' # Default KDF mode
    }

    for part in parts[1:]:
        part = part.strip()
        if part.startswith('--compression='):
            comp = part.split('=')[1]
            if comp not in ['none', 'lz4', 'zstd']:
                raise ValueError(f"Invalid compression method: {comp}")
            if comp == 'zstd' and not zstd:
                raise ValueError("Zstd requested but library not available.")
            params['compression'] = comp
        elif part == '--permute':
            params['permute'] = True
        elif part.startswith('--mode='):
            mode = part.split('=')[1]
            if mode not in KDF_MODES:
                 raise ValueError(f"Invalid KDF mode: {mode}. Must be one of {list(KDF_MODES.keys())}")
            params['mode'] = mode
        else:
            raise ValueError(f"Unknown V-config parameter: {part}")
            
    return version, params


# --- V2/V4 Block Logic (Abstraction) ---

def _pack_data_to_block(
    data: bytes, master_key: bytes, version: int, permute: bool, compression: str, mode: str, kdf_content_hash: bytes
) -> bytes:
    """Packs raw file data into a single Qeltrix V2 or V4 block (Header + Encrypted Data)."""
    cfg = BLOCK_CONFIGS.get(version)
    if not cfg:
        raise ValueError(f"Unsupported block version: V{version}")
        
    # 1. Compress
    compressed_data = compress_data(data, compression)

    # 2. Derive Key & Generate Salt
    salt = secrets.token_bytes(cfg['SALT_SIZE'])
    # CRITICAL FIX: Pass kdf_content_hash (which is calculated based on mode)
    block_key = get_derived_key(master_key, salt, version, mode, kdf_content_hash)
    
    # 3. Permute
    permuted_data = apply_permute(compressed_data, block_key, permute)

    # 4. Generate IV/Nonce & Hash Head
    data_hash = hashlib.sha256(permuted_data).digest()
    nonce = data_hash[:cfg['NONCE_LEN']]
    
    # 5. Encrypt (AEAD)
    cipher = cfg['CIPHER'](block_key)
    # AAD contains everything needed to confirm decryption context
    aad = struct.pack('<I', version) + salt + str(permute).encode() + compression.encode() + mode.encode()
    encrypted_data_with_tag = cipher.encrypt(nonce, permuted_data, aad)
    
    # 6. Assemble Block Header
    block_data_length = len(encrypted_data_with_tag)
    block_header = (
        b'QLT' + struct.pack('<B', version) + 
        struct.pack('<H', cfg['SALT_SIZE']) + salt + 
        data_hash + # Hash of permuted/compressed data (32)
        struct.pack('<I', block_data_length) 
    )
    
    return block_header + encrypted_data_with_tag

def _unpack_block_to_data(
    block_data: bytes, master_key: bytes, version: int, permute: bool, compression: str, mode: str, kdf_content_hash: bytes
) -> bytes:
    """Unpacks a Qeltrix V2 or V4 block back into raw file data."""
    cfg = BLOCK_CONFIGS.get(version)
    if not cfg:
        raise ValueError(f"Unsupported block version: V{version}")

    # 1. Parse Block Header
    header_len = 6 + cfg['SALT_SIZE'] + 32 + 4 # Fixed header size for V5 blocks
    if len(block_data) < header_len:
        raise ValueError("Block data is too short for header parsing.")
        
    header_offset = 0
    # QLTX/Version is 4+1 byte; Salt size is 2 bytes (H=16)
    salt_size = struct.unpack('<H', block_data[header_offset+4:header_offset+6])[0]
    salt_start = header_offset + 6
    salt = block_data[salt_start:salt_start+salt_size]
    data_hash_start = salt_start + salt_size
    data_hash = block_data[data_hash_start:data_hash_start+32]
    block_data_length_start = data_hash_start + 32
    block_data_length = struct.unpack('<I', block_data[block_data_length_start:block_data_length_start+4])[0]
    
    encrypted_data_start = block_data_length_start + 4
    encrypted_data_with_tag = block_data[encrypted_data_start:encrypted_data_start+block_data_length]
    
    if len(encrypted_data_with_tag) != block_data_length:
        raise ValueError("Block data length mismatch.")

    # 2. Derive Key 
    # CRITICAL FIX: Pass the kdf_content_hash retrieved from VFS metadata
    block_key = get_derived_key(master_key, salt, version, mode, kdf_content_hash) 
    
    # 3. Decrypt (AEAD)
    nonce = data_hash[:cfg['NONCE_LEN']]
    cipher = cfg['CIPHER'](block_key)
    aad = struct.pack('<I', version) + salt + str(permute).encode() + compression.encode() + mode.encode()

    try:
        permuted_data = cipher.decrypt(nonce, encrypted_data_with_tag, aad)
    except Exception as e:
        raise RuntimeError(f"Decryption/Tag verification failed for V{version} block: {e}")

    # 4. Verify Permutation Hash
    actual_hash = hashlib.sha256(permuted_data).digest()
    if actual_hash != data_hash:
        raise RuntimeError(f"Integrity check failed: Permuted data hash mismatch for V{version} block.")

    # 5. Un-permute
    compressed_data = apply_permute(permuted_data, block_key, permute)

    # 6. Decompress
    raw_data = decompress_data(compressed_data, compression)
    
    return raw_data


def handle_metadata_pack(metadata: Dict, public_key_path: Optional[str]) -> Tuple[int, bytes]:
    """Encrypts metadata if a public key is provided, or returns it unencrypted."""
    metadata_json = json.dumps(metadata).encode('utf-8')
    
    if public_key_path:
        # V5A Mode: Asymmetric Encryption
        public_key = load_rsa_key(public_key_path, is_private=False)
        metadata_mode = METADATA_MODE_ASYMMETRIC
        
        # 1. Generate Metadata Encryption Key (MEK)
        metadata_key = secrets.token_bytes(MEK_LEN)
        
        # 2. RSA-OAEP Encrypt the MEK
        encrypted_mek = public_key.encrypt(
            metadata_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Symmetrically Encrypt JSON Metadata
        nonce = secrets.token_bytes(MEK_NONCE_LEN)
        cipher = METADATA_CIPHER(metadata_key)
        encrypted_metadata_with_tag = cipher.encrypt(nonce, metadata_json, b'V5_METADATA_AAD')
        
        # 4. Assemble Encrypted Footer Block
        footer_block = (
            struct.pack('<I', len(encrypted_mek)) + encrypted_mek + # MEK length (4) + Encrypted MEK
            nonce + # Nonce (12)
            encrypted_metadata_with_tag # Encrypted JSON + Tag
        )
        return metadata_mode, footer_block
        
    else:
        # V5 Mode: Unencrypted Metadata
        metadata_mode = METADATA_MODE_NONE
        # The footer block is just the unencrypted JSON data
        return metadata_mode, metadata_json

def handle_metadata_unpack(private_key_path: Optional[str], file_handle: io.FileIO, metadata_start_offset: int, total_file_size: int, metadata_mode: int) -> Dict:
    """Decrypts or loads the V5 metadata based on the mode."""
    file_handle.seek(metadata_start_offset)
    
    if metadata_mode == METADATA_MODE_ASYMMETRIC:
        # V5A Mode: Asymmetric Decryption
        if not private_key_path:
            raise RuntimeError("Archive uses Asymmetric Metadata Encryption (V5A) but --private-key was not provided.")
            
        private_key = load_rsa_key(private_key_path, is_private=True)
        
        # 1. Read Encrypted MEK length
        mek_len_bytes = file_handle.read(4)
        if len(mek_len_bytes) < 4:
            raise IOError("Could not read MEK length from footer.")
        mek_len = struct.unpack('<I', mek_len_bytes)[0]

        # 2. Read Encrypted MEK
        encrypted_mek = file_handle.read(mek_len)
        
        # 3. Decrypt the MEK using RSA-OAEP
        try:
            metadata_key = private_key.decrypt(
                encrypted_mek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            raise RuntimeError(f"Failed to decrypt Metadata Key (MEK) using private key: {e}")
        
        # 4. Read Nonce
        nonce = file_handle.read(MEK_NONCE_LEN)
        
        # Calculate the exact length of the encrypted JSON data + Tag
        current_read_position = file_handle.tell()
        encrypted_data_length = total_file_size - FOOTER_SIZE_BYTES - current_read_position
        
        if encrypted_data_length <= MEK_TAG_LEN: 
             raise IOError("Encrypted metadata block is too short or corrupt.")
             
        encrypted_metadata_with_tag = file_handle.read(encrypted_data_length)

        # 5. Decrypt the JSON metadata
        cipher = METADATA_CIPHER(metadata_key)
        try:
            decrypted_json_bytes = cipher.decrypt(nonce, encrypted_metadata_with_tag, b'V5_METADATA_AAD')
            return json.loads(decrypted_json_bytes.decode('utf-8'))
        except Exception as e:
            raise RuntimeError(f"Failed to decrypt/verify metadata JSON using MEK: {e}")

    elif metadata_mode == METADATA_MODE_NONE:
        # V5 Mode: Unencrypted Metadata (JSON)
        metadata_length = total_file_size - FOOTER_SIZE_BYTES - metadata_start_offset
        metadata_json_bytes = file_handle.read(metadata_length)
        
        try:
            return json.loads(metadata_json_bytes.decode('utf-8'))
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to decode unencrypted metadata JSON: {e}")

    else:
        raise ValueError(f"Unknown metadata mode in header: {metadata_mode}")

# --- New Function for Parallel Packing ---

def _pack_file_worker(
    full_path: str, master_key: bytes, v_version: int, v_params: Dict[str, Any], root_path_len: int
) -> Tuple[str, bytes, Dict[str, Any]]:
    """Worker function to read, compress, encrypt a single file's content into a block."""
    relative_path = os.path.abspath(full_path)[root_path_len:]

    with open(full_path, 'rb') as f_in:
        raw_data = f_in.read()
    
    raw_data_hash = hashlib.sha256(raw_data).hexdigest()
    kdf_content_hash = get_mode_content_hash(raw_data, v_params['mode']) 
    
    block_data = _pack_data_to_block(
        raw_data, master_key, v_version, 
        permute=v_params['permute'], 
        compression=v_params['compression'],
        mode=v_params['mode'],
        kdf_content_hash=kdf_content_hash
    )
    
    # Return everything needed to write the block and update the final metadata
    file_metadata = {
        'path': relative_path,
        # block_offset and block_length will be set in the main thread
        'original_size': len(raw_data),
        'raw_data_hash': raw_data_hash, 
        'kdf_content_hash': kdf_content_hash.hex(), 
        'v_version': v_version,
        'v_params': v_params 
    }
    
    return relative_path, block_data, file_metadata
# --- New Function for Parallel Unpacking ---

def _unpack_block_worker(
    block_data: bytes, master_key: bytes, file_entry: Dict[str, Any]
) -> Tuple[str, Optional[bytes]]:
    """Worker function to decrypt, decompress a block and return the raw data."""
    try:
        kdf_content_hash_bytes = bytes.fromhex(file_entry['kdf_content_hash']) 
        
        raw_data = _unpack_block_to_data(
            block_data, master_key, file_entry['v_version'], 
            permute=file_entry['v_params']['permute'],
            compression=file_entry['v_params']['compression'],
            mode=file_entry['v_params']['mode'],
            kdf_content_hash=kdf_content_hash_bytes 
        )
        # Perform integrity check *after* decryption/decompression
        raw_data_hash_expected = file_entry.get('raw_data_hash') 
        if raw_data_hash_expected:
            raw_data_hash_actual = hashlib.sha256(raw_data).hexdigest()
            if raw_data_hash_actual != raw_data_hash_expected:
                 # Raise error to be caught by the worker and returned in the Future
                 raise RuntimeError(f"Integrity Failure: Hash mismatch for {file_entry['path']}")

        return file_entry['path'], raw_data
        
    except Exception as e:
        print(f"Error processing {file_entry['path']}: {e}", file=sys.stderr)
        return file_entry['path'], None

def pack_folder_to_v5(
    folder_path: str, output_file: str, master_key: bytes, v_version: int, v_params: Dict[str, Any], public_key_path: Optional[str]
):
    """Walks a directory, serializes files into Qeltrix V2/V4 blocks, and creates a V5 archive."""
    metadata_mode = METADATA_MODE_ASYMMETRIC if public_key_path else METADATA_MODE_NONE
    mode_str = "V5A (Asymmetric)" if metadata_mode == METADATA_MODE_ASYMMETRIC else "V5 (Unencrypted)"
    
    print(f"Starting {mode_str} pack of '{folder_path}' to '{output_file}'...")
    print(f"Using V{v_version} block config: {v_params}")
    
    metadata = {
        'files': [],
        'timestamp': time.time(),
        'root_dir': os.path.basename(os.path.abspath(folder_path)),
        'metadata_mode': metadata_mode,
        'v_version': V5_VERSION
    }
    
    root_path_len = len(os.path.abspath(folder_path)) + 1 
    
    with open(output_file, 'wb') as fout:
        # 1. Write V5 File Header (QLTX + Version + Mode)
        fout.write(V5_MAGIC) 
        fout.write(struct.pack('<I', V5_VERSION)) 
        fout.write(struct.pack('<B', metadata_mode)) # Write 1 byte mode flag
        
        # 2. Iterate through files, submit to executor, and write results sequentially
        
        # --- File Collection & Submission ---
        all_files_to_pack = []
        for dirpath, dirnames, filenames in os.walk(folder_path):
            dirnames.sort() 
            filenames.sort()

            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                if os.path.isfile(full_path):
                    all_files_to_pack.append(full_path)
        
        # Dictionary to hold the Futures
        futures = {}
        
        print(f"Submitting {len(all_files_to_pack)} files to the worker pool...")
        
        # Use ProcessPoolExecutor for parallel block creation
        with ProcessPoolExecutor() as executor:
            for full_path in all_files_to_pack:
                # Submit task to worker
                future = executor.submit(
                    _pack_file_worker, 
                    full_path, master_key, v_version, v_params, root_path_len
                )
                futures[future] = full_path # Store future with the path for context

            # --- Result Collection and Sequential Writing ---
            for future in as_completed(futures):
                full_path = futures[future] # Retrieve the original path
                try:
                    # Get the results from the worker
                    relative_path, block_data, file_metadata = future.result()
                    
                    print(f"  Writing file: {relative_path}")
                    
                    block_start_offset = fout.tell()
                    fout.write(block_data)
                    
                    # Complete metadata
                    file_metadata['block_offset'] = block_start_offset
                    file_metadata['block_length'] = len(block_data)
                    
                    # Record metadata for this file
                    metadata['files'].append(file_metadata)

                except Exception as e:
                    print(f"Error in parallel packing for {os.path.abspath(full_path)}: {e}. Skipping file.", file=sys.stderr)

        # IMPORTANT: Sort metadata files based on block_offset after parallel processing
        metadata['files'].sort(key=lambda x: x['block_offset'])

        # 3. Write V5 Encrypted/Unencrypted Metadata Footer
        metadata_mode_used, footer_block = handle_metadata_pack(metadata, public_key_path)
        metadata_start_offset = fout.tell()
        fout.write(footer_block)
        
        # 4. Write Footer Index (Points to the start of the metadata block)
        footer_index = struct.pack('<Q', metadata_start_offset)
        fout.write(footer_index)
        
    print(f"\nSuccessfully created {mode_str} archive: {output_file}")


def process_v5(archive_file: str, master_key: bytes, private_key_path: Optional[str], action: str, vfs_path: Optional[str] = None, offset: Optional[int] = None, length: Optional[int] = None, output_dir: Optional[str] = None) -> Optional[bytes]:
    """Centralized function to handle unpack and seek operations."""
    
    # 1. Read Header and Footer Index
    try:
        with open(archive_file, 'rb') as fin:
            # Read V5 header (QLTX + Version + Mode)
            fin.seek(0)
            magic = fin.read(4)
            version = struct.unpack('<I', fin.read(4))[0]
            metadata_mode_bytes = fin.read(1)
            
            if magic != V5_MAGIC or version != V5_VERSION:
                raise ValueError(f"Not a valid Qeltrix V{V5_VERSION} archive file.")

            metadata_mode = struct.unpack('<B', metadata_mode_bytes)[0]
            
            # Read footer index (8 bytes from EOF)
            fin.seek(-FOOTER_SIZE_BYTES, os.SEEK_END)
            footer_index_bytes = fin.read(FOOTER_SIZE_BYTES)
            
            # The file pointer is now at EOF, which gives us the total file size
            total_file_size = fin.tell() 
            
            metadata_start_offset = struct.unpack('<Q', footer_index_bytes)[0]
            
            # 2. Decrypt/Load Metadata
            metadata = handle_metadata_unpack(private_key_path, fin, metadata_start_offset, total_file_size, metadata_mode)
            
    except Exception as e:
        print(f"Error processing V5 archive metadata (Mode: {metadata_mode}): {e}")
        return None

    if action == "unpack":
            os.makedirs(output_dir, exist_ok=True)
            mode_str = "V5A (Asymmetric)" if metadata_mode == METADATA_MODE_ASYMMETRIC else "V5 (Unencrypted)"
            print(f"Starting {mode_str} unpack of '{archive_file}' to '{output_dir}'...")
            
            futures = {}
            
            with open(archive_file, 'rb') as fin:
                
                # --- Submission Phase ---
                print(f"Submitting {len(metadata['files'])} blocks for parallel decryption and decompression...")
                with ProcessPoolExecutor() as executor:
                    for file_entry in metadata['files']:
                        block_offset = file_entry['block_offset']
                        block_length = file_entry['block_length']
                        relative_path = file_entry['path']
                        
                        # Read block data *in the main thread* to avoid file handle conflicts in process pool
                        fin.seek(block_offset)
                        block_data = fin.read(block_length)
                        
                        # Submit the block data and metadata to the worker
                        future = executor.submit(_unpack_block_worker, block_data, master_key, file_entry)
                        futures[future] = relative_path
                        
                    # --- Result Collection and Disk Writing Phase ---
                    for future in as_completed(futures):
                        relative_path = futures[future]
                        print(f"  Processing result for: {relative_path}")

                        try:
                            relative_path_result, raw_data = future.result()
                            
                            if raw_data is not None:
                                output_path = os.path.join(output_dir, relative_path_result)
                                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                                
                                with open(output_path, 'wb') as fout:
                                    fout.write(raw_data)
                                    
                                raw_data_hash_actual = hashlib.sha256(raw_data).hexdigest()
                                print(f"  Extracted OK (SHA256: {raw_data_hash_actual[:8]}...)")

                        except Exception as e:
                            print(f"Error writing/processing {relative_path}: {e}. Skipping file.", file=sys.stderr)

            print(f"\nSuccessfully extracted V5 archive to: {output_dir}")
            return None

    elif action == "seek":
        print(f"Starting V5 seek in '{archive_file}' for VFS path: {vfs_path}")
        
        file_entry = next((f for f in metadata['files'] if f['path'] == vfs_path), None)
        
        if not file_entry:
            raise FileNotFoundError(f"File not found in VFS metadata: {vfs_path}")

        block_offset = file_entry['block_offset']
        block_length = file_entry['block_length']
        v_version = file_entry['v_version']
        v_params = file_entry['v_params']
        kdf_content_hash_bytes = bytes.fromhex(file_entry['kdf_content_hash']) # <-- Retrieve and convert KDF hash

# 3. Read the Block (in main thread)
        with open(archive_file, 'rb') as fin:
            fin.seek(block_offset)
            block_data = fin.read(block_length)
        
        # 4. Unpack the Block in a worker process
        print("  Submitting block for parallel decryption...")
        with ProcessPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_unpack_block_worker, block_data, master_key, file_entry)
            
            relative_path_result, raw_data = future.result()
            
            if raw_data is None:
                raise RuntimeError(f"Block decryption/integrity failed for seek target: {vfs_path}")
            
        # 5. Extract the requested range (VFS Seek)
        start = offset
        end = offset + length
        
        if end > len(raw_data):
            print(f"Warning: Requested length ({length}) exceeds file size ({len(raw_data)}) from offset {offset}. Returning data until EOF.")
            end = len(raw_data)
        
        return raw_data[start:end]


# --- CLI and Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="Qeltrix V5.5 Folder Archiver using V2/V4 block formats. Supports optional asymmetric key encryption for metadata."
    )
    parser.add_argument("cmd", choices=["pack", "unpack", "seek"], help="Command: 'pack', 'unpack', or 'seek'.")
    parser.add_argument(
        "--key", 
        default="", 
        help="Master key (password) for block content encryption/decryption. (Default: empty string)."
    )
    
    # Asymmetric Keys are now optional
    parser.add_argument("--private-key", default=None, help="Path to the RSA private key (OPTIONAL, required only for V5A archives).")
    parser.add_argument("--public-key", default=None, help="Path to the RSA public key (OPTIONAL, if provided, V5A mode is used).")
    
    # Subcommand for packing (archiving)
    pack_group = parser.add_argument_group("Pack Arguments (for 'pack' command)")
    pack_group.add_argument("--input-folder", help="Input folder path to archive.")
    pack_group.add_argument("--output-file", help="Output V5 archive file path (e.g., archive.q5).")
    pack_group.add_argument(
        "-v", "--v-config", 
        type=str,
        default="4,--compression=lz4,--permute,--mode=two_pass",
        help="V2/V4 Block Config: 'VERSION,[--compression|--permute|--mode=two_pass|single_pass_firstn]'"
    )
    
    # Subcommand for seeking
    seek_group = parser.add_argument_group("Seek Arguments (for 'seek' command)")
    seek_group.add_argument("--input-file", help="Input V5 archive file path.")
    seek_group.add_argument("--vfs-path", help="The relative path of the file inside the V5 archive to seek into.")
    seek_group.add_argument("--offset", type=int, default=0, help="Start offset in bytes within the VFS file.")
    seek_group.add_argument("--length", type=int, default=1024, help="Number of bytes to read from the offset.")
    seek_group.add_argument("--output", default=None, help="Optional file path to write seek output. If not specified, prints metadata.")

    # Subcommand for unpacking
    unpack_group = parser.add_argument_group("Unpack Arguments (for 'unpack' command)")
    unpack_group.add_argument("--output-folder", help="Output folder path to extract files into.")

    args = parser.parse_args()

    master_key = args.key.encode('utf-8')
    try:

        if args.cmd == "pack":
            if not args.input_folder or not args.output_file:
                parser.error("The 'pack' command requires --input-folder and --output-file.")
            
            if args.public_key:
                 # V5A mode, verify key existence
                 if not os.path.exists(args.public_key):
                     parser.error(f"Public key file not found: {args.public_key}")

            v_version, v_params = parse_v_config(args.v_config)
            
            pack_folder_to_v5(
                args.input_folder, args.output_file, master_key, 
                v_version, v_params, args.public_key
            )
            
        elif args.cmd == "unpack":
            if not args.input_file or not args.output_folder:
                parser.error("The 'unpack' command requires --input-file and --output-folder.")
                
            # Private key is checked inside process_v5 based on archive mode
            process_v5(
                args.input_file, master_key, args.private_key, "unpack", 
                output_dir=args.output_folder
            )
            
        elif args.cmd == "seek":
            if not args.input_file or not args.vfs_path:
                parser.error("The 'seek' command requires --input-file and --vfs-path.")
                
            # Private key is checked inside process_v5 based on archive mode
            try:
                data = process_v5(
                    args.input_file, master_key, args.private_key, "seek",
                    vfs_path=args.vfs_path, offset=args.offset, length=args.length
                )
                
                if data is not None:
                    if args.output:
                        with open(args.output, "wb") as f:
                            f.write(data)
                        print(f"\n[qeltrix seek] Wrote {len(data)} bytes from VFS offset {args.offset} to {args.output}")
                    else:
                        preview = data[:100]
                        print(f"\n[qeltrix seek] Read {len(data)} bytes from VFS offset {args.offset}.")
                        print(f"--- Data Preview (First {len(preview)} bytes) ---")
                        print(preview.hex())
                        print("--------------------------------------")
            except Exception as e:
                print(f"Seek failed: {e}")
    except Exception as e :
            print(f"\nFATAL ERROR: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
