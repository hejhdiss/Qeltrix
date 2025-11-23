#!/usr/bin/env python3
"""
Qeltrix (.qltx) - Content-derived, parallel, streaming obfuscation container (PoC)

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.

Features:
 - two_pass mode: content-derived key from full compressed stream (disk-backed, no large RAM).
 - single_pass_firstN: single-pass head-derived key from first N raw bytes (bounded memory).
 - per-block LZ4 compression, deterministic permutation, XOR keystream, AEAD (ChaCha20-Poly1305).
 - parallel compression, streaming write, footer index with per-block metadata and global checksum.
 - block_size is stored in header (required for correct decoding).
"""

import os, io, json, struct, secrets, hashlib, tempfile, shutil, time
from typing import Optional, Dict
import lz4.frame
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# === Format identifiers ===
MAGIC = b"QLTX"        # Qeltrix file magic
VERSION = 1
RESERVED = b"\x00\x00\x00"
# New delimiter to clearly separate the last ciphertext block from the JSON footer.
FOOTER_DELIMITER = b"QDELIMITERQ" 

def _uint32_be(i: int) -> bytes:
    return struct.pack(">I", i)
def _read_uint32_be(b: bytes) -> int:
    return struct.unpack(">I", b)[0]

def derive_key_from_h(h_bytes: bytes, salt: bytes, info: bytes = b"qeltrix-v1") -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    return hkdf.derive(h_bytes)

# --- Helpers used by workers / main process ---
def worker_compress_block(data: bytes) -> bytes:
    return lz4.frame.compress(data)

def permute_bytes_buf(buf: bytearray, seed_bytes: bytes) -> bytearray:
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
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(seed + struct.pack(">I", counter)).digest())
        counter += 1
    return bytes(out[:length])

# ----------------------
# PACK: two_pass and single_pass_firstN
# ----------------------
def pack_qeltrix(
    infile: str,
    outfile: str,
    block_size: int = 1 << 20,
    permute: bool = True,
    mode: str = "two_pass",   # "two_pass" or "single_pass_firstN"
    head_bytes: int = 1 << 20,
    workers: Optional[int] = None,
    tempdir: Optional[str] = None
):
    """
    Pack 'infile' -> 'outfile' (.qltx)
    mode:
      - two_pass: compress whole stream first (disk temp files) -> compute H -> derive key -> encrypt blocks
      - single_pass_firstN: single-pass, derive key from first 'head_bytes' raw bytes (bounded memory)
    """
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
                    f = pex.submit(worker_compress_block, chunk)
                    in_futures[f] = idx
                    idx += 1
                    # bound in-flight
                    while len(in_futures) >= max_in_flight:
                        done, _ = wait(in_futures.keys(), return_when=FIRST_COMPLETED)
                        for d in done:
                            comp = d.result()
                            orig_index = in_futures.pop(d)
                            tmpf = os.path.join(tempdir, f"blk_{orig_index:08d}.lz4")
                            with open(tmpf, "wb") as tf:
                                tf.write(comp)
                            sha.update(comp)
                            comp_files.append((tmpf, orig_index))
                # drain remaining
                for d in list(in_futures.keys()):
                    comp = d.result()
                    orig_index = in_futures.pop(d)
                    tmpf = os.path.join(tempdir, f"blk_{orig_index:08d}.lz4")
                    with open(tmpf, "wb") as tf:
                        tf.write(comp)
                    sha.update(comp)
                    comp_files.append((tmpf, orig_index))

            H = sha.digest()
            salt = secrets.token_bytes(16)
            key = derive_key_from_h(H, salt)
            meta = {
                "orig_size": os.path.getsize(infile),
                "block_size": block_size,
                "compression": "lz4",
                "format": "qltx_v1",
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
                
                # --- FIX: Write Delimiter before footer ---
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
                "compression": "lz4",
                "format": "qltx_v1",
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
                # We'll read, submit compress tasks, and collect compressed results as they finish.
                # We delay writing header until we compute head_hash (derived from head_buf).
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
                    # submit compression
                    f = pex.submit(worker_compress_block, chunk)
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
                            key = derive_key_from_h(head_hash, salt)
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
                    key = derive_key_from_h(head_hash, salt)
                    chacha = ChaCha20Poly1305(key)
                    meta_bytes = json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")
                    outf.write(MAGIC); outf.write(bytes([VERSION])); outf.write(RESERVED)
                    outf.write(_uint32_be(len(meta_bytes))); outf.write(meta_bytes)
                    current_offset = outf.tell()
                
                # Header is now guaranteed to be written, and key/chacha initialized
                
                # Write compressed results in order (blocks 0..n)
                next_write = 0
                # total blocks known from results_map keys
                while True:
                    # wait until next_write available in results_map
                    # Note: Since we drained all futures, this should only wait if a block hasn't been added to results_map yet,
                    # which shouldn't happen if all futures are drained. We check if all results are processed.
                    if next_write not in results_map:
                        # Check if all blocks have been written
                        if next_write >= idx: # idx is the total number of blocks submitted
                             break
                        # We should not reach here if all futures are drained, but as a safeguard:
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
                    # continue until results_map exhausted

                # footer
                footer = {"blocks": block_index_entries, "global_ciphertext_sha256": global_sha.hexdigest()}
                footer_bytes = json.dumps(footer, separators=(",", ":"), sort_keys=True).encode("utf-8")
                
                # --- FIX: Write Delimiter before footer ---
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

# --------------------
# UNPACK (streaming) - supports both modes (auto-detect by meta fields)
# --------------------
def unpack_qeltrix(in_path: str, out_path: str, verify_global: bool = True):
    with open(in_path, "rb") as inf:
        magic = inf.read(4)
        if magic != MAGIC:
            raise ValueError("Not a Qeltrix (.qltx) file")
        ver = inf.read(1)[0]
        _ = inf.read(3)
        meta_len = _read_uint32_be(inf.read(4))
        meta_bytes = inf.read(meta_len)
        meta = json.loads(meta_bytes.decode("utf-8"))

        # --- FIX: read footer using delimiter ---
        file_size = os.path.getsize(in_path)
        
        # 1. Read the 4-byte footer length from the very end of the file
        inf.seek(-4, os.SEEK_END)
        footer_len = _read_uint32_be(inf.read(4))
        
        # 2. Calculate the offset where the footer JSON *must* start
        # The structure is: [Delimiter] [Footer JSON] [4-byte Length]
        delimiter_len = len(FOOTER_DELIMITER)
        footer_start_offset = file_size - 4 - footer_len
        delimiter_start_offset = footer_start_offset - delimiter_len
        
        # 3. Read the expected delimiter
        inf.seek(delimiter_start_offset)
        delimiter_check = inf.read(delimiter_len)
        
        if delimiter_check != FOOTER_DELIMITER:
             raise ValueError("File corruption or invalid format: Footer delimiter not found.")

        # 4. Read the footer JSON bytes exactly
        inf.seek(footer_start_offset)
        footer_bytes = inf.read(footer_len)
        
        # The error occurred here because previous bytes were garbage
        try:
            footer = json.loads(footer_bytes.decode("utf-8"))
        except UnicodeDecodeError as e:
            # Provide a clearer error message indicating the file structure is likely corrupted
            raise ValueError(
                f"Failed to decode footer JSON (Unicode error). "
                f"The file structure appears corrupt or the end-of-file offsets were wrong. "
                f"Original error: {e}"
            ) from e
        # --- END FIX ---
        
        blocks = footer["blocks"]
        global_sha_expected = footer.get("global_ciphertext_sha256")

        salt = bytes.fromhex(meta["salt"])
        permute = bool(meta.get("permute", True))

        # infer mode by presence of 'h' or 'head_hash'
        if "h" in meta:
            h = bytes.fromhex(meta["h"])
            key = derive_key_from_h(h, salt)
            mode_inferred = "two_pass"
        elif "head_hash" in meta:
            h = bytes.fromhex(meta["head_hash"])
            key = derive_key_from_h(h, salt)
            mode_inferred = "single_pass_firstN"
        else:
            raise ValueError("Cannot infer Qeltrix mode: missing 'h' or 'head_hash'")

        aead = ChaCha20Poly1305(key)

        # Verify global checksum if requested
        if verify_global and global_sha_expected:
            gh = hashlib.sha256()
            for ent in blocks:
                inf.seek(ent["offset"])
                ct = inf.read(ent["ciphertext_len"])
                gh.update(ct)
            if gh.hexdigest() != global_sha_expected:
                raise ValueError("Global ciphertext checksum mismatch - file corrupted or tampered")

        # decrypt blocks in original order and stream output
        blocks_sorted = sorted(blocks, key=lambda e: e["orig_index"])
        with open(out_path, "wb") as outf:
            for ent in blocks_sorted:
                inf.seek(ent["offset"])
                ct = inf.read(ent["ciphertext_len"])
                nonce = bytes.fromhex(ent["nonce"])
                # meta_bytes is the associated data for AEAD
                try:
                    xored = aead.decrypt(nonce, ct, meta_bytes)
                except Exception as e:
                    raise ValueError(f"Block authentication failed for block {ent['orig_index']} (Key or metadata mismatch).") from e
                
                # Check if h needs to be re-derived for single_pass_firstN
                if mode_inferred == "single_pass_firstN" and "head_hash" in meta:
                    h = bytes.fromhex(meta["head_hash"]) # use head_hash as the base for keys/seeds
                
                ks_seed = hashlib.sha256(h + salt + struct.pack(">I", ent["orig_index"]) + b"ks").digest()
                ks = keystream_from_seed(ks_seed, len(xored))
                permuted = bytes(a ^ b for a, b in zip(xored, ks))
                if permute:
                    buf = bytearray(permuted)
                    seed = hashlib.sha256(h + salt + struct.pack(">I", ent["orig_index"])).digest()
                    buf = unpermute_bytes_buf(buf, seed)
                    comp = bytes(buf)
                else:
                    comp = permuted
                dec = lz4.frame.decompress(comp)
                outf.write(dec)
    print(f"[qeltrix unpacked] -> {out_path} (mode inferred: {mode_inferred})")

# --------------------
# CLI
# --------------------
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Qeltrix (.qltx) pack/unpack tool | Copyright 2025 @hejhdiss(Muhammed Shafin P)")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("pack", help="pack file to .qltx")
    p.add_argument("infile")
    p.add_argument("outfile")
    p.add_argument("--block-size", type=int, default=1<<20, help="block size in bytes (will be stored in header)")
    p.add_argument("--no-permute", action="store_true", dest="no_permute")
    p.add_argument("--mode", choices=["two_pass","single_pass_firstN"], default="two_pass")
    p.add_argument("--head-bytes", type=int, default=1<<20, help="for single_pass_firstN: number of head bytes to derive key")
    p.add_argument("--workers", type=int, default=None)
    p.add_argument("--tempdir", default=None)

    q = sub.add_parser("unpack", help="unpack .qltx to file")
    q.add_argument("infile")
    q.add_argument("outfile")
    q.add_argument("--no-verify", action="store_true", dest="no_verify")

    args = ap.parse_args()
    if args.cmd == "pack":
        pack_qeltrix(args.infile, args.outfile, block_size=args.block_size,
                     permute=(not args.no_permute), mode=args.mode,
                     head_bytes=args.head_bytes, workers=args.workers, tempdir=args.tempdir)
    elif args.cmd == "unpack":
        unpack_qeltrix(args.infile, args.outfile, verify_global=(not args.no_verify))
    else:
        ap.print_help()
