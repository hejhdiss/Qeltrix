#!/usr/bin/env python3
"""
Qeltrix (.qltx) - Content-derived, parallel, streaming obfuscation container (PoC)

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.

Features (V2):
 - PARALLEL DECRYPTION & SEEKABILITY: Index supports fast parallel access and seeking.
 - Zstandard (zstd) compression support alongside LZ4.
 - Backwards compatibility with V1 files (implicit LZ4, different key derivation info).
 - two_pass mode: content-derived key from full compressed stream (disk-backed, no large RAM).
 - single_pass_firstN: single-pass head-derived key from first N raw bytes (bounded memory).
 - per-block compression, deterministic permutation, XOR keystream, AEAD (ChaCha20-Poly1305).
"""

import os, io, json, struct, secrets, hashlib, tempfile, shutil, time
from typing import Optional, Dict, List, Tuple
import lz4.frame
# Import zstandard conditionally, assuming it is installed alongside lz4.
try:
    import zstandard as zstd
except ImportError:
    zstd = None
    print("Warning: zstandard library not found. Zstd compression/decompression is disabled.")

from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# === Format identifiers ===
MAGIC = b"QLTX"        # Qeltrix file magic
VERSION = 2            # Current tool/format version
RESERVED = b"\x00\x00\x00"
FOOTER_DELIMITER = b"QDELIMITERQ" 

# Key derivation info strings (CRITICAL for backward compatibility)
KEY_INFO_V1 = b"qeltrix-v1"
KEY_INFO_V2 = b"qeltrix-v2"

def _uint32_be(i: int) -> bytes:
    return struct.pack(">I", i)
def _read_uint32_be(b: bytes) -> int:
    return struct.unpack(">I", b)[0]

def derive_key_from_h(h_bytes: bytes, salt: bytes, info: bytes) -> bytes:
    """Derives a 32-byte key using HKDF-SHA256 with a version-specific info string."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(h_bytes)

# --- Helpers used by workers / main process ---
def worker_compress_block(data: bytes, compression: str) -> bytes:
    """Worker function to compress a block using the specified algorithm."""
    if compression == "lz4":
        return lz4.frame.compress(data)
    elif compression == "zstd":
        if not zstd:
            raise ImportError("zstandard library required for zstd compression.")
        # Use a moderate compression level
        cctx = zstd.ZstdCompressor(level=3)
        return cctx.compress(data)
    else:
        raise ValueError(f"Unsupported compression type: {compression}")

def permute_bytes_buf(buf: bytearray, seed_bytes: bytes) -> bytearray:
    """Deterministically permutes a byte buffer."""
    import random
    r = random.Random(int.from_bytes(seed_bytes, "big"))
    n = len(buf)
    idx = list(range(n))
    r.shuffle(idx)
    out = bytearray(n)
    for i, j in enumerate(idx):
        out[i] = buf[j]
    return out

def unpermute_bytes_buf(buf: bytearray, seed_bytes: bytes) -> bytearray:
    """Reverses a deterministic permutation."""
    import random
    r = random.Random(int.from_bytes(seed_bytes, "big"))
    n = len(buf)
    idx = list(range(n))
    r.shuffle(idx)
    out = bytearray(n)
    for i, j in enumerate(idx):
        out[j] = buf[i]
    return out

def keystream_from_seed(seed: bytes, length: int) -> bytes:
    """Generates a pseudorandom keystream using SHA256 and a counter."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        # Use simple BE counter in struct.pack
        out.extend(hashlib.sha256(seed + struct.pack(">I", counter)).digest())
        counter += 1
    return bytes(out[:length])

# ----------------------
# PACK (V2 format)
# ----------------------
def pack_qeltrix(
    infile: str,
    outfile: str,
    block_size: int = 1 << 20,
    permute: bool = True,
    compression: str = "lz4",
    mode: str = "two_pass",
    head_bytes: int = 1 << 20,
    workers: Optional[int] = None,
    tempdir: Optional[str] = None
):
    """
    Pack 'infile' -> 'outfile' (.qltx) using the V2 format.
    """
    if compression == "zstd" and not zstd:
        raise RuntimeError("zstandard compression requested but zstandard library is not available.")
    if compression not in ["lz4", "zstd"]:
        raise ValueError("Compression must be 'lz4' or 'zstd'.")


    workers = workers or (os.cpu_count() or 2)
    tempdir = tempdir or tempfile.mkdtemp(prefix="qeltrix_temp_")
    max_in_flight = max(2, workers * 2)

    try:
        if mode == "two_pass":
            # PASS 1: parallel compress into temp files (bounded in-flight)
            comp_files = []
            sha = hashlib.sha256()
            idx = 0
            with open(infile, "rb") as inf, ProcessPoolExecutor(max_workers=workers) as pex:
                in_futures = {}
                while True:
                    chunk = inf.read(block_size)
                    if not chunk:
                        break
                    # Pass compression type to worker
                    f = pex.submit(worker_compress_block, chunk, compression)
                    in_futures[f] = idx
                    idx += 1
                    # bound in-flight
                    while len(in_futures) >= max_in_flight:
                        done, _ = wait(in_futures.keys(), return_when=FIRST_COMPLETED)
                        for d in done:
                            comp = d.result()
                            orig_index = in_futures.pop(d)
                            tmpf = os.path.join(tempdir, f"blk_{orig_index:08d}.comp")
                            with open(tmpf, "wb") as tf:
                                tf.write(comp)
                            sha.update(comp)
                            comp_files.append((tmpf, orig_index))
                # drain remaining
                for d in list(in_futures.keys()):
                    comp = d.result()
                    orig_index = in_futures.pop(d)
                    tmpf = os.path.join(tempdir, f"blk_{orig_index:08d}.comp")
                    with open(tmpf, "wb") as tf:
                        tf.write(comp)
                    sha.update(comp)
                    comp_files.append((tmpf, orig_index))

            H = sha.digest()
            salt = secrets.token_bytes(16)
            # Use V2 info string for key derivation
            key = derive_key_from_h(H, salt, info=KEY_INFO_V2)
            meta = {
                "orig_size": os.path.getsize(infile),
                "block_size": block_size,
                "compression": compression, # Store compression type
                "format": f"qltx_v{VERSION}",
                "salt": salt.hex(),
                "h": H.hex(),
                "permute": bool(permute),
                "mode_tag": hashlib.sha256(salt + b"qeltrix_mode:two_pass").hexdigest(),
                "copyright": "@hejhdiss(Muhammed Shafin P)"
            }
            meta_bytes = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")

            # write header and encrypted blocks
            with open(outfile, "wb") as outf:
                outf.write(MAGIC); outf.write(bytes([VERSION])); outf.write(RESERVED)
                outf.write(_uint32_be(len(meta_bytes))); outf.write(meta_bytes)
                block_index_entries = []
                current_offset = outf.tell()
                chacha = ChaCha20Poly1305(key)
                global_sha = hashlib.sha256()
                # process each compressed temp file in orig_index order
                comp_files.sort(key=lambda x: x[1])
                for tmpf, orig_index in comp_files:
                    with open(tmpf, "rb") as tf:
                        comp_bytes = tf.read()
                    # permute
                    if permute:
                        seed = hashlib.sha256(H + salt + struct.pack(">I", orig_index)).digest()
                        buf = bytearray(comp_bytes)
                        buf = permute_bytes_buf(buf, seed)
                        permuted = bytes(buf)
                    else:
                        permuted = comp_bytes
                    # xor keystream
                    ks_seed = hashlib.sha256(H + salt + struct.pack(">I", orig_index) + b"ks").digest()
                    ks = keystream_from_seed(ks_seed, len(permuted))
                    xored = bytes(a ^ b for a, b in zip(permuted, ks))
                    # AEAD encrypt
                    nonce = secrets.token_bytes(12)
                    ct = chacha.encrypt(nonce, xored, meta_bytes)
                    outf.write(ct)
                    global_sha.update(ct)
                    entry = {
                        "orig_index": orig_index,
                        "offset": current_offset,
                        "ciphertext_len": len(ct),
                        "compressed_len": len(comp_bytes),
                        "nonce": nonce.hex()
                    }
                    block_index_entries.append(entry)
                    current_offset += len(ct)
                    try: os.remove(tmpf)
                    except Exception: pass

                # footer with index and global ciphertext checksum
                footer = {"blocks": block_index_entries, "global_ciphertext_sha256": global_sha.hexdigest()}
                footer_bytes = json.dumps(footer, separators=(",", ":"), sort_keys=True).encode("utf-8")
                
                # Write Delimiter before footer
                outf.write(FOOTER_DELIMITER)
                outf.write(footer_bytes)
                outf.write(_uint32_be(len(footer_bytes)))
                
            print(f"[qeltrix packed: two_pass] -> {outfile}  blocks={len(block_index_entries)}")
            return

        elif mode == "single_pass_firstN":
            # Single-pass pipeline: derive key from first head_bytes of raw file.
            salt = secrets.token_bytes(16)
            mode_tag = hashlib.sha256(salt + b"qeltrix_mode:single_pass_firstN").hexdigest()
            meta = {
                "orig_size": os.path.getsize(infile),
                "block_size": block_size,
                "compression": compression, # Store compression type
                "format": f"qltx_v{VERSION}",
                "salt": salt.hex(),
                "permute": bool(permute),
                "mode_tag": mode_tag,
                "copyright": "HejHdiss (Muhammed Shafin P)"
            }

            head_buf = bytearray()
            head_remaining = head_bytes

            # parallel compression with bounded in-flight futures
            max_in_flight_local = max(2, workers * 2)
            futures_map = {}
            results_map: Dict[int, bytes] = {}
            block_index_entries = []
            global_sha = hashlib.sha256()

            with open(infile, "rb") as inf, open(outfile, "wb") as outf, ProcessPoolExecutor(max_workers=workers) as pex:
                idx = 0
                in_futures = []
                current_offset = 0 # Placeholder, will be updated when header is written
                
                while True:
                    chunk = inf.read(block_size)
                    if not chunk:
                        break
                    # update head buffer until we have head_bytes
                    if head_remaining > 0:
                        take = min(head_remaining, len(chunk))
                        head_buf.extend(chunk[:take])
                        head_remaining -= take
                    # submit compression, passing compression type
                    f = pex.submit(worker_compress_block, chunk, compression)
                    futures_map[f] = idx
                    in_futures.append(f)
                    idx += 1
                    # bound in-flight
                    while len(in_futures) >= max_in_flight_local:
                        done, _ = wait(in_futures, return_when=FIRST_COMPLETED)
                        for d in done:
                            in_futures.remove(d)
                            comp = d.result()
                            i = futures_map.pop(d)
                            results_map[i] = comp
                        # if head_bytes reached and header not written, compute key and write header now
                        if head_remaining <= 0 and "head_hash" not in meta:
                            head_hash = hashlib.sha256(bytes(head_buf)).digest()
                            meta["head_hash"] = head_hash.hex()
                            key = derive_key_from_h(head_hash, salt, info=KEY_INFO_V2)
                            chacha = ChaCha20Poly1305(key)
                            meta_bytes = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")
                            outf.write(MAGIC); outf.write(bytes([VERSION])); outf.write(RESERVED)
                            outf.write(_uint32_be(len(meta_bytes))); outf.write(meta_bytes)
                            current_offset = outf.tell()
                # drain remaining futures
                for d in list(in_futures):
                    comp = d.result()
                    i = futures_map.pop(d)
                    results_map[i] = comp

                # If head_bytes never reached (small file), derive head_hash now
                if "head_hash" not in meta:
                    head_hash = hashlib.sha256(bytes(head_buf)).digest()
                    meta["head_hash"] = head_hash.hex()
                    key = derive_key_from_h(head_hash, salt, info=KEY_INFO_V2)
                    chacha = ChaCha20Poly1305(key)
                    meta_bytes = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")
                    outf.write(MAGIC); outf.write(bytes([VERSION])); outf.write(RESERVED)
                    outf.write(_uint32_be(len(meta_bytes))); outf.write(meta_bytes)
                    current_offset = outf.tell()
                
                # Header is now guaranteed to be written, and key/chacha initialized
                
                # Write compressed results in order (blocks 0..n)
                next_write = 0
                while True:
                    if next_write not in results_map:
                        if next_write >= idx: # idx is the total number of blocks submitted
                             break
                        time.sleep(0.001)
                        continue
                        
                    comp_bytes = results_map.pop(next_write)
                    if permute:
                        seed = hashlib.sha256(bytes.fromhex(meta["head_hash"]) + salt + struct.pack(">I", next_write)).digest()
                        buf = bytearray(comp_bytes)
                        buf = permute_bytes_buf(buf, seed)
                        permuted = bytes(buf)
                    else:
                        permuted = comp_bytes
                    ks_seed = hashlib.sha256(bytes.fromhex(meta["head_hash"]) + salt + struct.pack(">I", next_write) + b"ks").digest()
                    ks = keystream_from_seed(ks_seed, len(permuted))
                    xored = bytes(a ^ b for a, b in zip(permuted, ks))
                    nonce = secrets.token_bytes(12)
                    # NOTE: meta_bytes must be re-encoded here since 'head_hash' was added to meta
                    current_meta_bytes = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")
                    ct = chacha.encrypt(nonce, xored, current_meta_bytes)
                    outf.write(ct)
                    global_sha.update(ct)
                    entry = {
                        "orig_index": next_write,
                        "offset": current_offset,
                        "ciphertext_len": len(ct),
                        "compressed_len": len(comp_bytes),
                        "nonce": nonce.hex()
                    }
                    block_index_entries.append(entry)
                    current_offset += len(ct)
                    next_write += 1

                # footer
                footer = {"blocks": block_index_entries, "global_ciphertext_sha256": global_sha.hexdigest()}
                footer_bytes = json.dumps(footer, separators=(",", ":"), sort_keys=True).encode("utf-8")
                
                # Write Delimiter before footer
                outf.write(FOOTER_DELIMITER)
                outf.write(footer_bytes)
                outf.write(_uint32_be(len(footer_bytes)))

            print(f"[qeltrix packed: single_pass_firstN] -> {outfile} blocks={len(block_index_entries)}")
            return

        else:
            raise ValueError("Unknown mode: choose 'two_pass' or 'single_pass_firstN'")

    finally:
        # cleanup tempdir
        try:
            shutil.rmtree(tempdir)
        except Exception:
            pass


# --- Unpack Helper Functions ---

def read_qltx_metadata(in_path: str) -> Tuple[Dict, Dict, bytes, bytes]:
    """Reads header metadata, footer index, global H/head_hash, and key derivation salt.
       Includes logic for backward compatibility with V1 files.
    """
    with open(in_path, "rb") as inf:
        # Read Header
        magic = inf.read(4)
        if magic != MAGIC:
            raise ValueError("Not a Qeltrix (.qltx) file")
        
        # --- Version Reading and Backward Compatibility Check ---
        ver_byte = inf.read(1)
        # Assume V1 if the version byte is missing (highly unlikely with V2 packer) or is 1
        ver = ver_byte[0] if ver_byte else 1 
        
        # Handle unsupported versions first
        if ver > VERSION:
            raise ValueError(f"File version {ver} is newer than tool version {VERSION}. Compatibility is not guaranteed.")
        
        _ = inf.read(3)
        meta_len = _read_uint32_be(inf.read(4))
        meta_bytes = inf.read(meta_len)
        meta = json.loads(meta_bytes.decode("utf-8"))

        # Read Footer using delimiter (footer structure is consistent across V1/V2)
        file_size = os.path.getsize(in_path)
        inf.seek(-4, os.SEEK_END)
        footer_len = _read_uint32_be(inf.read(4))
        
        delimiter_len = len(FOOTER_DELIMITER)
        footer_start_offset = file_size - 4 - footer_len
        delimiter_start_offset = footer_start_offset - delimiter_len
        
        inf.seek(delimiter_start_offset)
        delimiter_check = inf.read(delimiter_len)
        
        if delimiter_check != FOOTER_DELIMITER:
             raise ValueError("File corruption or invalid format: Footer delimiter not found.")

        inf.seek(footer_start_offset)
        footer_bytes = inf.read(footer_len)
        
        try:
            footer = json.loads(footer_bytes.decode("utf-8"))
        except UnicodeDecodeError as e:
            raise ValueError(
                f"Failed to decode footer JSON (Unicode error). "
                f"Original error: {e}"
            ) from e

        # Derive key information
        salt = bytes.fromhex(meta["salt"])
        if "h" in meta:
            h = bytes.fromhex(meta["h"])
        elif "head_hash" in meta:
            h = bytes.fromhex(meta["head_hash"])
        else:
            raise ValueError("Cannot infer Qeltrix mode: missing 'h' or 'head_hash'")
        
        # --- V1/V2 Parameter Determination ---
        if ver == 1:
            # V1 files implicitly use lz4 and the V1 key info string
            key_info = KEY_INFO_V1
            compression = "lz4"
        elif ver == 2:
            key_info = KEY_INFO_V2
            compression = meta.get("compression", "lz4")
        else:
            # Should be covered by the initial check, but good for robustness
            raise ValueError(f"Unsupported Qeltrix file version: {ver}")

        # Store determined version and compression type in meta for consistency
        meta["file_version"] = ver
        meta["compression"] = compression
        
        # Key derivation uses the correct, version-specific info string
        key = derive_key_from_h(h, salt, info=key_info)
        
        return meta, footer, key, meta_bytes

def worker_decrypt_block(
    in_path: str,
    ent: Dict,
    key: bytes,
    meta_bytes: bytes,
    h: bytes,
    salt: bytes,
    permute: bool,
    compression: str,
) -> Tuple[int, bytes]:
    """Worker function for parallel decryption, unpermutation, and decompression of a single block."""
    with open(in_path, "rb") as inf:
        inf.seek(ent["offset"])
        ct = inf.read(ent["ciphertext_len"])
    
    # 1. AEAD decrypt
    aead = ChaCha20Poly1305(key)
    nonce = bytes.fromhex(ent["nonce"])
    try:
        xored = aead.decrypt(nonce, ct, meta_bytes)
    except Exception as e:
        # Return index and None to signify authentication failure
        print(f"Error: Block {ent['orig_index']} authentication failed.")
        return ent["orig_index"], None

    # 2. XOR Keystream
    ks_seed = hashlib.sha256(h + salt + struct.pack(">I", ent["orig_index"]) + b"ks").digest()
    ks = keystream_from_seed(ks_seed, len(xored))
    permuted = bytes(a ^ b for a, b in zip(xored, ks))
    
    # 3. Unpermute
    if permute:
        buf = bytearray(permuted)
        seed = hashlib.sha256(h + salt + struct.pack(">I", ent["orig_index"])).digest()
        buf = unpermute_bytes_buf(buf, seed)
        comp = bytes(buf)
    else:
        comp = permuted

    # 4. Decompress
    try:
        if compression == "lz4":
            dec = lz4.frame.decompress(comp)
        elif compression == "zstd":
            if not zstd:
                raise ImportError("zstandard library required for zstd decompression.")
            dctx = zstd.ZstdDecompressor()
            dec = dctx.decompress(comp)
        else:
            raise ValueError(f"Unsupported compression type: {compression}")
    except Exception as e:
         # Return index and None to signify decompression failure
        print(f"Error: Block {ent['orig_index']} decompression failed: {e}")
        return ent["orig_index"], None
        
    return ent["orig_index"], dec


# --------------------
# UNPACK (parallel streaming)
# --------------------
def unpack_qeltrix(in_path: str, out_path: str, verify_global: bool = True, workers: Optional[int] = None):
    """
    Unpack .qltx to file using parallel decryption.
    """
    workers = workers or (os.cpu_count() or 2)
    meta, footer, key, meta_bytes = read_qltx_metadata(in_path)
    
    blocks = footer["blocks"]
    global_sha_expected = footer.get("global_ciphertext_sha256")
    permute = bool(meta.get("permute", True))
    # 'compression' is guaranteed to be set in meta by read_qltx_metadata
    compression = meta["compression"] 
    
    # infer H (could be 'h' or 'head_hash')
    h = bytes.fromhex(meta.get("h") or meta.get("head_hash"))
    salt = bytes.fromhex(meta["salt"])

    # Verify global checksum if requested
    if verify_global and global_sha_expected:
        gh = hashlib.sha256()
        with open(in_path, "rb") as inf:
            for ent in blocks:
                inf.seek(ent["offset"])
                ct = inf.read(ent["ciphertext_len"])
                gh.update(ct)
        if gh.hexdigest() != global_sha_expected:
            raise ValueError("Global ciphertext checksum mismatch - file corrupted or tampered")

    # Parallel decrypt and stream output
    blocks_by_index = {ent["orig_index"]: ent for ent in blocks}
    max_index = max(blocks_by_index.keys()) if blocks_by_index else -1
    
    with ProcessPoolExecutor(max_workers=workers) as pex, open(out_path, "wb") as outf:
        futures = []
        for index, ent in blocks_by_index.items():
            f = pex.submit(
                worker_decrypt_block, 
                in_path, ent, key, meta_bytes, h, salt, permute, compression
            )
            futures.append(f)

        # Collect results in a map to ensure writing in original order
        results_map: Dict[int, bytes] = {}
        next_write_index = 0
        
        while next_write_index <= max_index or futures:
            # Check for completed futures
            done, futures = wait(futures, timeout=0.001, return_when=FIRST_COMPLETED)
            
            for d in done:
                index, data = d.result()
                if data is None:
                    # Authentication or decompression failed, stop processing
                    raise ValueError(f"Critical error during decryption/decompression of block {index}.")
                results_map[index] = data
            
            # Write out contiguous blocks starting from next_write_index
            while next_write_index in results_map:
                outf.write(results_map.pop(next_write_index))
                next_write_index += 1
                
    print(f"[qeltrix unpacked] -> {out_path} (format: V{meta['file_version']}, compression: {compression})")

# --------------------
# SEEK (random access)
# --------------------

def seek_qeltrix(in_path: str, offset: int, length: int, workers: Optional[int] = None) -> bytes:
    """
    Reads 'length' bytes starting at 'offset' from the virtual uncompressed stream.
    """
    workers = workers or (os.cpu_count() or 2)
    meta, footer, key, meta_bytes = read_qltx_metadata(in_path)

    orig_size = meta["orig_size"]
    block_size = meta["block_size"]
    blocks = sorted(footer["blocks"], key=lambda e: e["orig_index"]) # Ensure blocks are ordered
    permute = bool(meta.get("permute", True))
    # 'compression' is guaranteed to be set in meta by read_qltx_metadata
    compression = meta["compression"]
    h = bytes.fromhex(meta.get("h") or meta.get("head_hash"))
    salt = bytes.fromhex(meta["salt"])

    # Clamp request to file bounds
    if offset >= orig_size:
        return b""
    if offset + length > orig_size:
        length = orig_size - offset

    # 1. Determine block range
    # Block index = floor(offset / block_size)
    start_block_index = offset // block_size
    end_block_index = (offset + length - 1) // block_size

    # 2. Determine slice within the raw decompressed data
    start_byte_in_first_block = offset % block_size
    
    # Total length of the final output buffer
    total_requested_length = length 
    
    # The actual blocks needed (Note: list slicing will be simpler if blocks were indexed 0..N-1)
    needed_blocks = [
        ent for ent in blocks 
        if start_block_index <= ent["orig_index"] <= end_block_index
    ]

    # 3. Parallel Decrypt/Decompress requested blocks
    with ProcessPoolExecutor(max_workers=workers) as pex:
        futures = []
        for ent in needed_blocks:
            f = pex.submit(
                worker_decrypt_block, 
                in_path, ent, key, meta_bytes, h, salt, permute, compression
            )
            futures.append(f)

        # Collect results in index order (required for concatenation)
        results = {}
        for f in futures:
            index, data = f.result()
            if data is None:
                raise ValueError(f"Critical error during decryption/decompression of block {index} for seek operation.")
            results[index] = data
        
        # Sort results by index
        decrypted_blocks = [results[i] for i in sorted(results.keys())]

    # 4. Concatenate and slice
    full_buffer = b"".join(decrypted_blocks)
    
    # Calculate starting index in the concatenated buffer
    # The start_block_index is the first block we retrieved. 
    # start_byte_in_first_block is the offset within that first block.
    buffer_start_index = start_byte_in_first_block

    # Calculate end index in the concatenated buffer (exclusive)
    buffer_end_index = buffer_start_index + total_requested_length
    
    return full_buffer[buffer_start_index:buffer_end_index]

# --------------------
# CLI
# --------------------
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Qeltrix (.qltx) pack/unpack/seek tool | Copyright 2025 @hejhdiss(Muhammed Shafin P)")
    sub = ap.add_subparsers(dest="cmd")
    
    # PACK sub-command
    p = sub.add_parser("pack", help="pack file to .qltx (creates V2 file)")
    p.add_argument("infile")
    p.add_argument("outfile")
    p.add_argument("--block-size", type=int, default=1<<20, help="block size in bytes (will be stored in header)")
    p.add_argument("--no-permute", action="store_true", dest="no_permute")
    # Added zstd support to compression choices
    p.add_argument("--compression", choices=["lz4", "zstd"], default="lz4", help="compression algorithm to use")
    p.add_argument("--mode", choices=["two_pass","single_pass_firstN"], default="two_pass")
    p.add_argument("--head-bytes", type=int, default=1<<20, help="for single_pass_firstN: number of head bytes to derive key")
    p.add_argument("--workers", type=int, default=None, help="number of parallel workers")
    p.add_argument("--tempdir", default=None)

    # UNPACK sub-command
    q = sub.add_parser("unpack", help="unpack .qltx to file (supports V1 and V2 files)")
    q.add_argument("infile")
    q.add_argument("outfile")
    q.add_argument("--no-verify", action="store_true", dest="no_verify")
    q.add_argument("--workers", type=int, default=None, help="number of parallel workers")

    # SEEK sub-command
    s = sub.add_parser("seek", help="read a byte range from the virtual uncompressed file (supports V1 and V2 files)")
    s.add_argument("infile")
    s.add_argument("offset", type=int, help="start offset in bytes")
    s.add_argument("length", type=int, help="number of bytes to read")
    s.add_argument("--output", default=None, help="optional file path to write the output data to. If not specified, output goes to stdout.")
    s.add_argument("--workers", type=int, default=None, help="number of parallel workers")

    args = ap.parse_args()
    if args.cmd == "pack":
        pack_qeltrix(args.infile, args.outfile, block_size=args.block_size,
                     permute=(not args.no_permute), compression=args.compression, 
                     mode=args.mode, head_bytes=args.head_bytes, 
                     workers=args.workers, tempdir=args.tempdir)
    elif args.cmd == "unpack":
        unpack_qeltrix(args.infile, args.outfile, 
                       verify_global=(not args.no_verify), workers=args.workers)
    elif args.cmd == "seek":
        try:
            data = seek_qeltrix(args.infile, args.offset, args.length, workers=args.workers)
            if args.output:
                with open(args.output, "wb") as f:
                    f.write(data)
                print(f"[qeltrix seek] Wrote {len(data)} bytes from offset {args.offset} to {args.output}")
            else:
                # Print to stdout, useful for piping binary data
                import sys
                sys.stdout.buffer.write(data)
                print(f"\n[qeltrix seek] Read {len(data)} bytes from offset {args.offset} (output sent to stdout)")
        except Exception as e:
            print(f"Error during seek operation: {e}")
    else:
        ap.print_help()
