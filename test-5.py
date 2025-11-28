#!/usr/bin/env python3
"""
test-5.py
This automated test script verifies the functionality and integrity of the 
Qeltrix V5 Archiver ('qeltrix-5.py'). It covers various test cases including 
different encryption block versions (V2/V4), compression types (LZ4/ZSTD), 
key derivation modes, and both V5 (unencrypted) and V5A (asymmetrically 
encrypted) metadata modes.

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.
"""
import os
import shutil
import subprocess
import time
import secrets # Used for generating random master keys

# --- New Cryptography Imports for RSA Key Generation ---
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
# --------------------------------------------------------

# --- Configuration ---
QELTRIX_SCRIPT = 'qeltrix-5.py'
INPUT_DIR = 'test_input_data'
OUTPUT_DIR = 'test_output_data'
KEY_DIR = 'test_keys'

# Update file extension to .qltx
ARCHIVE_V5A_LZ4 = os.path.join(OUTPUT_DIR, 'archive_v5a_lz4.qltx')
ARCHIVE_V5A_ZSTD = os.path.join(OUTPUT_DIR, 'archive_v5a_zstd.qltx')
ARCHIVE_V5_V4 = os.path.join(OUTPUT_DIR, 'archive_v5_v4.qltx')
ARCHIVE_V5_V2 = os.path.join(OUTPUT_DIR, 'archive_v5_v2.qltx')
ARCHIVE_V5_NOKEY = os.path.join(OUTPUT_DIR, 'archive_v5_nokey.qltx')

# Dynamic keys generated at runtime
MASTER_KEY_A = secrets.token_hex(32)
MASTER_KEY_B = secrets.token_hex(32)
MASTER_KEY_C = secrets.token_hex(32)

# File paths and their expected content/hashes
FILES = {
    'file_a.bin': b'\x42' * 4096,  # 4KB placeholder data (0x42 is 'B')
    'sub_folder/file_b.txt': b'This is a secret message inside file_b.\n'
}

# --- Utility Functions ---

def create_environment():
    """Sets up directories, dummy files, and RSA keys using Python's cryptography library."""
    print("--- 1. SETTING UP TEST ENVIRONMENT ---")
    
    # Cleanup previous runs
    if os.path.exists(INPUT_DIR):
        shutil.rmtree(INPUT_DIR)
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    if os.path.exists(KEY_DIR):
        shutil.rmtree(KEY_DIR)
        
    os.makedirs(INPUT_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(KEY_DIR, exist_ok=True)

    # Create dummy files
    for rel_path, content in FILES.items():
        full_path = os.path.join(INPUT_DIR, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'wb') as f:
            f.write(content)
        print(f"Created dummy file: {full_path}")

    # --- Generate RSA keys using cryptography library ---
    PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
    PUBLIC_KEY_PATH = os.path.join(KEY_DIR, 'public.pem')
    
    try:
        # 1. Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # 2. Serialize and save the private key (No encryption)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # 3. Derive and save the public key
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        print("Generated RSA key pair using Python cryptography successfully.")
    except Exception as e:
        print(f"Error generating keys using cryptography: {e}")
        raise
            
    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

def run_qeltrix(cmd: str, **kwargs) -> subprocess.CompletedProcess:
    """Runs the qeltrix script with given arguments."""
    args = [QELTRIX_SCRIPT, cmd]
    
    # Process keyword arguments into command line flags
    for key, value in kwargs.items():
        if value is not None:
            # Converts --v_config to -v and handles other args like --key
            flag = f"--{key.replace('_', '-')}" if len(key) > 1 else f"-{key}"
            if key == 'v_config':
                 # Special handling for -v flag
                args.extend(['-v', str(value)])
            elif key == 'key' and value == "OMIT":
                # Skip adding --key
                continue
            else:
                args.extend([flag, str(value)])
            
    # Prepend python3
    command = ['python3'] + args
    print(f"\n$ {' '.join(command)}")
    # Use text=True for stdout/stderr decoding
    result = subprocess.run(command, capture_output=True, text=True, env=os.environ) 
    print(result.stdout)
    if result.stderr:
        print(f"--- STDERR ---\n{result.stderr}\n--------------")
    return result

def check_file_integrity(original_path_map: dict, unpacked_root: str) -> bool:
    """Compares the content of all original files with their unpacked counterparts."""
    print("--- Verifying file integrity ---")
    all_ok = True
    for rel_path, original_content in original_path_map.items():
        unpacked_path = os.path.join(unpacked_root, rel_path)
        
        if not os.path.exists(unpacked_path):
            print(f"[FAIL] Missing file: {unpacked_path}")
            all_ok = False
            continue

        try:
            with open(unpacked_path, 'rb') as f:
                unpacked_content = f.read()
        except IOError:
            print(f"[FAIL] Could not read unpacked file: {unpacked_path}")
            all_ok = False
            continue


        if unpacked_content == original_content:
            print(f"[PASS] {rel_path}: Content matches.")
        else:
            # For debugging, show content start
            orig_hex = original_content[:20].hex()
            unpacked_hex = unpacked_content[:20].hex()
            print(f"[FAIL] {rel_path}: Content mismatch.")
            print(f"   Original Start: {orig_hex}")
            print(f"   Unpacked Start: {unpacked_hex}")
            all_ok = False
            
    return all_ok

# --- Test Scenarios ---

def test_v5a_mode(private_key_path: str, public_key_path: str):
    """Tests V5A mode (Asymmetric Metadata Encryption) with multiple compression options."""
    print("\n\n#################################################")
    print("## TEST SCENARIO A: V5A (Asymmetric Metadata) ##")
    print("#################################################")
    
    # --- A.1. V5A + LZ4 Compression ---
    print("\n--- A.1. PACK/UNPACK/SEEK (V5A, LZ4) ---")
    
    # Pack
    result = run_qeltrix(
        "pack",
        input_folder=INPUT_DIR,
        output_file=ARCHIVE_V5A_LZ4,
        public_key=public_key_path,
        key=MASTER_KEY_A,
        v_config="4,--compression=lz4,--permute,--mode=single_pass_firstn"
    )
    assert result.returncode == 0 and os.path.exists(ARCHIVE_V5A_LZ4), "A.1 Pack (LZ4) failed."
    
    # Unpack
    UNPACK_V5A_LZ4 = os.path.join(OUTPUT_DIR, 'v5a_unpacked_lz4')
    os.makedirs(UNPACK_V5A_LZ4, exist_ok=True)
    result = run_qeltrix(
        "unpack",
        input_file=ARCHIVE_V5A_LZ4,
        output_folder=UNPACK_V5A_LZ4,
        private_key=private_key_path,
        key=MASTER_KEY_A
    )
    assert result.returncode == 0, "A.1 Unpack (LZ4) failed."
    assert check_file_integrity(FILES, UNPACK_V5A_LZ4), "A.1 Integrity check (LZ4) failed."
    
    # Seek
    expected_seek_data = FILES['file_a.bin'][:20].hex()
    result = run_qeltrix(
        "seek",
        input_file=ARCHIVE_V5A_LZ4,
        vfs_path="file_a.bin",
        private_key=private_key_path,
        key=MASTER_KEY_A,
        offset=0,
        length=20
    )
    assert result.returncode == 0, "A.1 Seek (LZ4) failed."
    assert expected_seek_data in result.stdout.replace('\n', ''), "A.1 Seek content mismatch (LZ4)."
    print("[TEST A.1. PASS]")

    # --- A.2. V5A + ZSTANDARD Compression ---
    print("\n--- A.2. PACK/UNPACK (V5A, ZSTD) ---")
    
    # Pack
    result = run_qeltrix(
        "pack",
        input_folder=INPUT_DIR,
        output_file=ARCHIVE_V5A_ZSTD,
        public_key=public_key_path,
        key=MASTER_KEY_B,
        v_config="4,--compression=zstd,--permute,--mode=two_pass"
    )
    assert result.returncode == 0 and os.path.exists(ARCHIVE_V5A_ZSTD), "A.2 Pack (ZSTD) failed."
    
    # Unpack
    UNPACK_V5A_ZSTD = os.path.join(OUTPUT_DIR, 'v5a_unpacked_zstd')
    os.makedirs(UNPACK_V5A_ZSTD, exist_ok=True)
    result = run_qeltrix(
        "unpack",
        input_file=ARCHIVE_V5A_ZSTD,
        output_folder=UNPACK_V5A_ZSTD,
        private_key=private_key_path,
        key=MASTER_KEY_B
    )
    assert result.returncode == 0, "A.2 Unpack (ZSTD) failed."
    assert check_file_integrity(FILES, UNPACK_V5A_ZSTD), "A.2 Integrity check (ZSTD) failed."
    print("[TEST A.2. PASS]")

    # --- A.3. Failure Test (Missing Private Key) ---
    print("\n--- A.3. UNPACK FAILURE (Missing Private Key) ---")
    result = run_qeltrix(
        "unpack",
        input_file=ARCHIVE_V5A_LZ4,
        output_folder=os.path.join(OUTPUT_DIR, 'fail_test'),
        key=MASTER_KEY_A # Private key is missing
    )
    
    # The unpack should fail because it needs the private key to decrypt metadata.
    expected_error_msg = "Archive uses Asymmetric Metadata Encryption (V5A) but --private-key was not provided."
    full_output = result.stdout + result.stderr

    # 1. Assert that the correct error message is present in the output
    assert expected_error_msg in full_output, f"A.3 Failure test did not find expected error message: '{expected_error_msg}' in output: {full_output}"
    
    # 2. Assert that the command failed with a non-zero return code (CRITICAL for CLI error handling)
    if result.returncode == 0:
        # If we reach here, the script printed the error but returned success, which is incorrect behavior.
        # This will raise a much more descriptive error if the target script is buggy.
        raise AssertionError(f"A.3 Failure test failed: Qeltrix returned success code (0) despite printing the error message. Return code must be non-zero on error.")

    print("[TEST A.3. PASS]")


def test_v5_mode():
    """Tests V5 mode (Unencrypted Metadata) with V4, V2, and no-key options."""
    print("\n\n#################################################")
    print("## TEST SCENARIO B: V5 (Unencrypted Metadata) ##")
    print("#################################################")

    # --- B.1. V5 + V4 (AES-GCM) Mode ---
    print("\n--- B.1. PACK/UNPACK/SEEK (V5, V4/AES-GCM) ---")
    
    # Pack (V4)
    result = run_qeltrix(
        "pack",
        input_folder=INPUT_DIR,
        output_file=ARCHIVE_V5_V4,
        key=MASTER_KEY_C,
        v_config="4,--compression=none,--permute,--mode=two_pass"
    )
    assert result.returncode == 0 and os.path.exists(ARCHIVE_V5_V4), "B.1 Pack (V4) failed."
    
    # Unpack (V4)
    UNPACK_V5_V4 = os.path.join(OUTPUT_DIR, 'v5_unpacked_v4')
    os.makedirs(UNPACK_V5_V4, exist_ok=True)
    result = run_qeltrix(
        "unpack",
        input_file=ARCHIVE_V5_V4,
        output_folder=UNPACK_V5_V4,
        key=MASTER_KEY_C
    )
    assert result.returncode == 0, "B.1 Unpack (V4) failed."
    assert check_file_integrity(FILES, UNPACK_V5_V4), "B.1 Integrity check (V4) failed."
    
    # Seek (V4)
    expected_seek_data = FILES['file_a.bin'][:20].hex()
    result = run_qeltrix(
        "seek",
        input_file=ARCHIVE_V5_V4,
        vfs_path="file_a.bin", 
        key=MASTER_KEY_C,
        offset=0,
        length=20
    )
    assert result.returncode == 0, "B.1 Seek (V4) failed."
    assert expected_seek_data in result.stdout.replace('\n', ''), "B.1 Seek content mismatch (V4)."
    print("[TEST B.1. PASS]")
    
    # --- B.2. V5 + V2 (ChaCha20-Poly1305) Mode ---
    print("\n--- B.2. PACK/UNPACK (V5, V2/ChaCha20) ---")
    
    # Pack (V2) - Note: V2 is simplified block version
    result = run_qeltrix(
        "pack",
        input_folder=INPUT_DIR,
        output_file=ARCHIVE_V5_V2,
        key=MASTER_KEY_A,
        v_config="2,--compression=none" # V2 block format
    )
    assert result.returncode == 0 and os.path.exists(ARCHIVE_V5_V2), "B.2 Pack (V2) failed."
    
    # Unpack (V2)
    UNPACK_V5_V2 = os.path.join(OUTPUT_DIR, 'v5_unpacked_v2')
    os.makedirs(UNPACK_V5_V2, exist_ok=True)
    result = run_qeltrix(
        "unpack",
        input_file=ARCHIVE_V5_V2,
        output_folder=UNPACK_V5_V2,
        key=MASTER_KEY_A
    )
    assert result.returncode == 0, "B.2 Unpack (V2) failed."
    assert check_file_integrity(FILES, UNPACK_V5_V2), "B.2 Integrity check (V2) failed."
    print("[TEST B.2. PASS]")

    # --- B.3. V5 + No Master Key (--key OMITTED) ---
    # This tests the archiver's ability to handle encryption with a default/null key 
    # when the user omits the --key flag.
    print("\n--- B.3. PACK/UNPACK (V5, No Key Provided) ---")

    # Pack (No Key)
    result = run_qeltrix(
        "pack",
        input_folder=INPUT_DIR,
        output_file=ARCHIVE_V5_NOKEY,
        key="OMIT", # Special keyword to omit the --key flag
        v_config="4,--compression=none"
    )
    assert result.returncode == 0 and os.path.exists(ARCHIVE_V5_NOKEY), "B.3 Pack (No Key) failed."
    
    # Unpack (No Key)
    UNPACK_V5_NOKEY = os.path.join(OUTPUT_DIR, 'v5_unpacked_nokey')
    os.makedirs(UNPACK_V5_NOKEY, exist_ok=True)
    result = run_qeltrix(
        "unpack",
        input_file=ARCHIVE_V5_NOKEY,
        output_folder=UNPACK_V5_NOKEY,
        key="OMIT" # Special keyword to omit the --key flag
    )
    
    # Assert successful unpacking, meaning the script gracefully handled the missing key
    assert result.returncode == 0, "B.3 Unpack (No Key) failed (The archiver should default to a null key)."
    assert check_file_integrity(FILES, UNPACK_V5_NOKEY), "B.3 Integrity check (No Key) failed."
    print("[TEST B.3. PASS]")


def cleanup():
    """Removes all test artifacts."""
    print("\n--- 3. CLEANUP ---")
    shutil.rmtree(INPUT_DIR, ignore_errors=True)
    shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
    shutil.rmtree(KEY_DIR, ignore_errors=True)
    print("Cleanup complete.")

# --- Main Execution ---

def main_test():
    start_time = time.time()
    try:
        if not os.path.exists(QELTRIX_SCRIPT):
            print(f"Error: Qeltrix script '{QELTRIX_SCRIPT}' not found. Please ensure it is in the current directory.")
            return

        private_key_path, public_key_path = create_environment()
        
        test_v5a_mode(private_key_path, public_key_path)
        test_v5_mode()
        
    except Exception as e:
        print(f"\nFATAL ERROR DURING TESTING: {e}")
    finally:
        cleanup()
        end_time = time.time()
        print(f"\n=======================================================")
        print(f"AUTOMATED TESTING COMPLETE. Time taken: {end_time - start_time:.2f} seconds.")
        print("=======================================================")

if __name__ == "__main__":
    main_test()
