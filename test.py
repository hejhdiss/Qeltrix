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

QELTRIX_SCRIPT = "qeltrix.py"
TEST_DIR = "qeltrix_v1_test_data"
TEST_FILE_CONTENT = b"The original V1 test file content. Testing only two_pass and single_pass_firstN. " * 300 

# --- Helper Functions (Minimal set for V1) ---
def create_test_files():
    os.makedirs(TEST_DIR, exist_ok=True)
    with open(os.path.join(TEST_DIR, "source.txt"), "wb") as f:
        f.write(TEST_FILE_CONTENT)
    print(f"Created source file: {os.path.join(TEST_DIR, 'source.txt')} ({len(TEST_FILE_CONTENT)} bytes)")

def run_qeltrix_cmd(command: str, *args):
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
    with open(path, "rb") as f:
        content = f.read()
    if content == expected_content:
        print(f"✅ Content verification successful: {path}")
    else:
        raise ValueError(f"❌ Content verification FAILED for {path}!")

def cleanup():
    if os.path.exists(TEST_DIR):
        import shutil
        shutil.rmtree(TEST_DIR)
        print(f"\nCleaned up directory: {TEST_DIR}")
# --- Test Cases ---

def test_v1_twopass():
    print("\n" + "="*50)
    print("=== Test Case 1: V1 two_pass (Default) ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v1_twopass.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v1_twopass_unpacked.txt")
    
    # PACK (two_pass is default)
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "4096")
    
    # UNPACK
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v1_single_pass_firstn():
    print("\n" + "="*50)
    print("=== Test Case 2: V1 single_pass_firstN (Head-derived Key) ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v1_singlepass.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v1_singlepass_unpacked.txt")

    # PACK (single_pass_firstN, setting head_bytes to 5KB for our test file)
    run_qeltrix_cmd("pack", source, qltx_file, "--mode", "single_pass_firstN", "--head-bytes", "5120")
    
    # UNPACK (key derived from content head)
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)


# --- Main Execution ---

if __name__ == "__main__":
    try:
        cleanup() 
        create_test_files()
        
        test_v1_twopass()
        test_v1_single_pass_firstn()

        print("\n" + "#"*60)
        print("### ALL QELTRIX V1 FUNCTIONALITY TESTS PASSED! ###")
        print("#"*60)

    except Exception as e:
        print("\n" + "!"*60)
        print(f"!!! A QELTRIX V1 TEST FAILED: {e} !!!")
        print("!"*60)
        sys.exit(1)
        
    finally:
        cleanup()
