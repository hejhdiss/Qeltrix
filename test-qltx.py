#!/usr/bin/env python3
"""
Qeltrix (.qltx) - Content-derived, parallel, streaming obfuscation container (PoC)

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.
"""
import os
import subprocess
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

QELTRIX_SCRIPT = "qltx.py" 
TEST_DIR = "qeltrix_full_test_data"
TEST_FILE_CONTENT = b"This is the source file for Qeltrix full functional testing. The quick brown fox jumps over the lazy dog. " * 800 

# --- Helper Functions ---

def create_test_files():
    os.makedirs(TEST_DIR, exist_ok=True)
    with open(os.path.join(TEST_DIR, "source.txt"), "wb") as f:
        f.write(TEST_FILE_CONTENT)
    print(f"Created source file: {os.path.join(TEST_DIR, 'source.txt')} ({len(TEST_FILE_CONTENT)} bytes)")

def generate_rsa_keys():
    recipient_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_paths = {
        "recipient_pub": os.path.join(TEST_DIR, "recipient_pub.pem"),
        "recipient_priv": os.path.join(TEST_DIR, "recipient_priv.pem"),
        "signer_priv": os.path.join(TEST_DIR, "signer_priv.pem"),
        "signer_pub": os.path.join(TEST_DIR, "signer_pub.pem"),
    }
    # Key generation and saving logic
    for name, path in key_paths.items():
        key = recipient_priv_key if "recipient_priv" in name else (recipient_priv_key.public_key() if "recipient_pub" in name else (signer_priv_key if "signer_priv" in name else signer_priv_key.public_key()))
        encoding = serialization.Encoding.PEM
        format_type = serialization.PrivateFormat.PKCS8 if "priv" in name else serialization.PublicFormat.SubjectPublicKeyInfo
        encryption_alg = serialization.NoEncryption() if "priv" in name else None
        with open(path, "wb") as f:
            if "priv" in name: f.write(key.private_bytes(encoding, format_type, encryption_alg))
            else: f.write(key.public_bytes(encoding, format_type))
    print("Generated RSA key pairs.")
    return key_paths

def run_qeltrix_cmd(command: str, *args):
    full_cmd = [sys.executable, QELTRIX_SCRIPT, command] + list(args)
    print(f"\n$ {' '.join(full_cmd)}")
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    
    if result.stderr:
        print("--- DISPATCHER/BACKEND STDERR ---")
        print(result.stderr.strip())
        print("---------------------------------")
    
    if result.returncode != 0:
        raise RuntimeError(f"Qeltrix command '{command}' failed with exit code {result.returncode}")
        
    print(result.stdout.strip())
    return result

def verify_file_content(path, expected_content):
    with open(path, "rb") as f: content = f.read()
    if content == expected_content:
        print(f"✅ Content verification successful: {path}")
    else:
        raise ValueError(f"❌ Content verification FAILED for {path}! Expected {len(expected_content)} bytes, got {len(content)}.")

def cleanup():
    if os.path.exists(TEST_DIR):
        import shutil
        shutil.rmtree(TEST_DIR)
        print(f"\nCleaned up directory: {TEST_DIR}")

# --- Test Cases ---

def test_v3_symmetric_default():
    print("\n" + "="*60)
    print("=== Test 1: V3 Symmetric (Modern Default, Cipher specified) ===")
    print("="*60)
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v3_symm_default.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v3_symm_unpacked.txt")
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "4096", "--cipher", "chacha20-poly1305")
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v1_legacy_path():
    print("\n" + "="*60)
    print("=== Test 2: V1 Legacy Path (Minimal Args) ===")
    print("="*60)
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v1_legacy.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v1_legacy_unpacked.txt")
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "8192", "--mode", "two_pass")
    # This unpack command will now route to qeltrix-2.py and succeed.
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v2_feature_zstd():
    print("\n" + "="*60)
    print("=== Test 3: V2 Feature (Zstandard Compression) ===")
    print("="*60)
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v2_zstd.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v2_zstd_unpacked.txt")
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "16384", "--compression", "zstd")
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v3a_asymmetric_signed(keys):
    print("\n" + "="*60)
    print("=== Test 4: V3-A (Asymmetric Key Transport + Signing) ===")
    print("="*60)
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v3a_asymm_signed.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v3a_asymm_signed_unpacked.txt")
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "4096", 
                    "--pubkey", keys["recipient_pub"], "--signkey", keys["signer_priv"])
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file, 
                    "--privkey", keys["recipient_priv"], "--verifykey", keys["signer_pub"])
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v3a_seek_operation(keys):
    print("\n" + "="*60)
    print("=== Test 5: V3-A Seek Operation (Block Access) ===")
    print("="*60)
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "seek_test.qltx")
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "1024", 
                    "--pubkey", keys["recipient_pub"])
    OFFSET = 500
    LENGTH = 4500 
    expected_data = TEST_FILE_CONTENT[OFFSET:OFFSET+LENGTH]
    seek_output_file = os.path.join(TEST_DIR, "seek_output.bin")
    run_qeltrix_cmd("seek", qltx_file, str(OFFSET), str(LENGTH), 
                    "--privkey", keys["recipient_priv"], "--output", seek_output_file)
    print(f"[qltx seek] Verification of {len(expected_data)} bytes...")
    verify_file_content(seek_output_file, expected_data)

# --- Main Execution ---

if __name__ == "__main__":
    try:
        cleanup() 
        create_test_files()
        keys = generate_rsa_keys()
        
        test_v3_symmetric_default()
        test_v1_legacy_path() 
        test_v2_feature_zstd()
        test_v3a_asymmetric_signed(keys)
        test_v3a_seek_operation(keys)

        print("\n" + "#"*70)
        print("### ALL QELTRIX SYSTEM FUNCTIONALITY TESTS PASSED SUCCESSFULLY! ###")
        print("### Dispatcher logic, all versions, and all commands validated. ###")
        print("#"*70)

    except Exception as e:
        print("\n" + "!"*70)
        print(f"!!! FATAL QELTRIX SYSTEM TEST FAILURE: {type(e).__name__}: {e} !!!")
        print("!"*70)
        sys.exit(1)
        
    finally:
        cleanup()
