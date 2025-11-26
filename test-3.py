#!/usr/bin/env python3
"""
Qeltrix (.qltx) - Content-derived, parallel, streaming obfuscation container (PoC)

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.
"""
import os
import subprocess
import time
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

QELTRIX_SCRIPT = "qeltrix-3.py"
TEST_DIR = "qeltrix_test_data"
TEST_FILE_CONTENT = b"This is a test file for Qeltrix PoC. The quick brown fox jumps over the lazy dog. " * 500 # Approx 30KB

# --- Helper Functions ---

def create_test_files():
    """Create directory and a source file for packing."""
    os.makedirs(TEST_DIR, exist_ok=True)
    with open(os.path.join(TEST_DIR, "source.txt"), "wb") as f:
        f.write(TEST_FILE_CONTENT)
    print(f"Created source file: {os.path.join(TEST_DIR, 'source.txt')} ({len(TEST_FILE_CONTENT)} bytes)")

def generate_rsa_keys():
    """Generate RSA keys for V3-A asymmetric mode and signing."""
    # Recipient Key Pair (for DEK encryption)
    recipient_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    recipient_pub_key = recipient_priv_key.public_key()
    
    # Signer Key Pair (for metadata signing)
    signer_priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_pub_key = signer_priv_key.public_key()

    # Save to PEM files
    key_paths = {
        "recipient_pub": os.path.join(TEST_DIR, "recipient_pub.pem"),
        "recipient_priv": os.path.join(TEST_DIR, "recipient_priv.pem"),
        "signer_priv": os.path.join(TEST_DIR, "signer_priv.pem"),
        "signer_pub": os.path.join(TEST_DIR, "signer_pub.pem"),
    }
    
    with open(key_paths["recipient_pub"], "wb") as f:
        f.write(recipient_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    with open(key_paths["recipient_priv"], "wb") as f:
        f.write(recipient_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(key_paths["signer_priv"], "wb") as f:
        f.write(signer_priv_key.private_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(key_paths["signer_pub"], "wb") as f:
        f.write(signer_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Generated RSA key pairs.")
    return key_paths

def run_qeltrix_cmd(command: str, *args):
    """Execute a qeltrix command and return the result."""
    full_cmd = [sys.executable, QELTRIX_SCRIPT, command] + list(args)
    print(f"\n$ {' '.join(full_cmd)}")
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("--- STDERR ---")
        print(result.stderr)
        print("--------------")
        raise RuntimeError(f"Qeltrix command '{command}' failed with exit code {result.returncode}")
        
    print(result.stdout.strip())
    return result

def verify_file_content(path, expected_content):
    """Read a file and compare its content."""
    with open(path, "rb") as f:
        content = f.read()
    if content == expected_content:
        print(f"✅ Content verification successful: {path}")
    else:
        raise ValueError(f"❌ Content verification FAILED for {path}! Expected {len(expected_content)} bytes, got {len(content)}.")

def cleanup():
    """Remove the test directory and all its contents."""
    if os.path.exists(TEST_DIR):
        import shutil
        shutil.rmtree(TEST_DIR)
        print(f"\nCleaned up directory: {TEST_DIR}")

# --- Test Cases ---

def test_v3_symmetric(keys):
    print("\n" + "="*50)
    print("=== Test Case 1: V3 Symmetric (Content-Derived Key) ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v3_symm.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v3_symm_unpacked.txt")
    
    # PACK (V3: no --pubkey)
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "1024", "--cipher", "aes256-gcm")
    
    # UNPACK
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)
    
def test_v3a_asymmetric_signed(keys):
    print("\n" + "="*50)
    print("=== Test Case 2: V3-A Asymmetric + Signed Metadata ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v3a_asymm_signed.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v3a_asymm_signed_unpacked.txt")
    
    # PACK (V3-A: use --pubkey, plus --signkey)
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "2048", 
                    "--pubkey", keys["recipient_pub"], "--signkey", keys["signer_priv"], 
                    "--compression", "zstd")
    
    # UNPACK (Requires --privkey)
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file, "--privkey", keys["recipient_priv"], 
                    "--verifykey", keys["signer_pub"])
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_seek_operation(keys):
    print("\n" + "="*50)
    print("=== Test Case 3: Seek Operation ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "seek_test.qltx")
    
    # PACK (V3-A mode for a better test)
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "1024", 
                    "--pubkey", keys["recipient_pub"])
    
    # Test 3.1: Read from the middle
    OFFSET = 500
    LENGTH = 1024
    expected_data = TEST_FILE_CONTENT[OFFSET:OFFSET+LENGTH]
    
    seek_result = run_qeltrix_cmd("seek", qltx_file, str(OFFSET), str(LENGTH), 
                                  "--privkey", keys["recipient_priv"])
    
    # The output is sent to stdout buffer, which we capture as bytes. 
    # The 'result.stdout' here contains the text from print() calls, 
    # not the binary data from sys.stdout.buffer.
    # A true test would require handling the binary output from the stdout buffer.
    # For this script, we'll write the output to a file and check that.
    
    seek_output_file = os.path.join(TEST_DIR, "seek_output.bin")
    run_qeltrix_cmd("seek", qltx_file, str(OFFSET), str(LENGTH), 
                    "--privkey", keys["recipient_priv"], "--output", seek_output_file)
    
    verify_file_content(seek_output_file, expected_data)

    # Test 3.2: Read spanning multiple blocks (Block size is 1024)
    OFFSET = 100
    LENGTH = 2500 
    expected_data_multi = TEST_FILE_CONTENT[OFFSET:OFFSET+LENGTH]
    
    seek_output_multi_file = os.path.join(TEST_DIR, "seek_output_multi.bin")
    run_qeltrix_cmd("seek", qltx_file, str(OFFSET), str(LENGTH), 
                    "--privkey", keys["recipient_priv"], "--output", seek_output_multi_file)
    
    verify_file_content(seek_output_multi_file, expected_data_multi)


# --- Main Execution ---

if __name__ == "__main__":
    try:
        cleanup() # Start fresh
        create_test_files()
        keys = generate_rsa_keys()
        
        # Run all test cases
        test_v3_symmetric(keys)
        test_v3a_asymmetric_signed(keys)
        test_seek_operation(keys)
        
        print("\n" + "#"*60)
        print("### ALL QELTRIX FUNCTIONALITY TESTS PASSED SUCCESSFULLY! ###")
        print("#"*60)

    except Exception as e:
        print("\n" + "!"*60)
        print(f"!!! A QELTRIX TEST FAILED: {e} !!!")
        print("!"*60)
        sys.exit(1)
        
    finally:
        # Optionally, comment this out if you want to inspect the generated files
        cleanup()
