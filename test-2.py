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

QELTRIX_SCRIPT = "qeltrix-2.py"
TEST_DIR = "qeltrix_v2_test_data"
TEST_FILE_CONTENT = b"A different test file content for V2: The quick brown fox jumps over the lazy dog. " * 300 
# The 'single_pass_firstN' test requires a source file > head_bytes (default is 1MB or 1<<20)
# We will explicitly set head_bytes to 5KB to work with our 20KB test file content.

# --- Helper Functions (Same as V3 but modified paths/script) ---
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

def test_v2_zstd_twopass():
    print("\n" + "="*50)
    print("=== Test Case 1: V2 two_pass + Zstandard Compression ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v2_zstd.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v2_zstd_unpacked.txt")
    
    # PACK (two_pass is default, explicitly using zstd)
    run_qeltrix_cmd("pack", source, qltx_file, "--block-size", "4096", "--compression", "zstd")
    
    # UNPACK
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v2_single_pass_firstn():
    print("\n" + "="*50)
    print("=== Test Case 2: V2 single_pass_firstN (Head-derived Key) ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v2_singlepass.qltx")
    unpacked_file = os.path.join(TEST_DIR, "v2_singlepass_unpacked.txt")

    # PACK (single_pass_firstN, setting head_bytes to 5KB)
    run_qeltrix_cmd("pack", source, qltx_file, "--mode", "single_pass_firstN", "--head-bytes", "5120")
    
    # UNPACK (key derived from content head)
    run_qeltrix_cmd("unpack", qltx_file, unpacked_file)
    verify_file_content(unpacked_file, TEST_FILE_CONTENT)

def test_v2_seek_operation():
    print("\n" + "="*50)
    print("=== Test Case 3: V2 Seek Operation (single_pass) ===")
    print("="*50)
    
    source = os.path.join(TEST_DIR, "source.txt")
    qltx_file = os.path.join(TEST_DIR, "v2_seek_test.qltx")
    
    # PACK using single_pass_firstN mode
    run_qeltrix_cmd("pack", source, qltx_file, "--mode", "single_pass_firstN", "--head-bytes", "5120")
    
    # Seek a large chunk
    OFFSET = 500
    LENGTH = 10000 
    expected_data = TEST_FILE_CONTENT[OFFSET:OFFSET+LENGTH]
    
    seek_output_file = os.path.join(TEST_DIR, "v2_seek_output.bin")
    run_qeltrix_cmd("seek", qltx_file, str(OFFSET), str(LENGTH), "--output", seek_output_file)
    
    verify_file_content(seek_output_file, expected_data)

# --- Main Execution ---

if __name__ == "__main__":
    try:
        cleanup() 
        create_test_files()
        
        test_v2_zstd_twopass()
        test_v2_single_pass_firstn()
        test_v2_seek_operation()

        print("\n" + "#"*60)
        print("### ALL QELTRIX V2 FUNCTIONALITY TESTS PASSED! ###")
        print("#"*60)

    except Exception as e:
        print("\n" + "!"*60)
        print(f"!!! A QELTRIX V2 TEST FAILED: {e} !!!")
        print("!"*60)
        sys.exit(1)
        
    finally:
        cleanup()
