#!/usr/bin/env python3
"""
Qeltrix (.qltx) - Content-derived, parallel, streaming obfuscation container (PoC)

Copyright (c) 2025 @hejhdiss(Muhammed Shafin P)
All rights reserved.
Licensed under GPLv3.
"""
import sys
import subprocess
import os
import struct
from typing import List, Tuple, Optional

# --- Qeltrix Header Detection Constants ---
MAGIC = b"QLTX"
HEADER_SIZE = 8 

def detect_qeltrix_version(filepath: str) -> Optional[str]:
    """Reads the first 8 bytes of a file to detect its Qeltrix version."""
    try:
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None

        with open(filepath, "rb") as f:
            header = f.read(HEADER_SIZE)

        if len(header) < HEADER_SIZE or header[:4] != MAGIC:
            return None 

        # CRITICAL FIX: Change from big-endian (>) to little-endian (<) 
        # to match how your backend scripts are saving the version.
        version_num = struct.unpack('<I', header[4:])[0] 

        if version_num >= 3:
            return 'v3' 
        elif version_num == 2:
            return 'v2' 
        elif version_num == 1:
            return 'v1' 
        else:
            return None

    except Exception:
        return None

def get_script_and_version_for_pack(args_to_pass: List[str]) -> Tuple[str, str]:
    """Determines the target script and version for the 'pack' command."""
    
    # 1. V3/V3-A
    if "--pubkey" in args_to_pass or any(flag in args_to_pass for flag in ["--cipher", "aes256-gcm", "chacha20-poly1305"]):
        return 'qeltrix-3.py', 'v3'
        
    # 2. V2
    if any(a == "--compression" and args_to_pass[args_to_pass.index(a) + 1] == "zstd" for a in args_to_pass if a == "--compression"):
        return 'qeltrix-2.py', 'v2'
        
    # 3. V1 (Default)
    return 'qeltrix.py', 'v1'

def get_script_and_version_for_decode(command: str, qltx_file: str) -> Tuple[str, str]:
    """Determines the target script and version for 'unpack' or 'seek'."""
    
    version = detect_qeltrix_version(qltx_file)
    
    if not version:
        raise ValueError(f"Input file '{qltx_file}' is not a valid Qeltrix container or version is unsupported.")

    # --- ROUTING LOGIC ---
    if version == 'v3':
        return 'qeltrix-3.py', version
    
    # V1 and V2 files MUST be routed to qeltrix-2.py for backwards compatibility.
    if version == 'v2' or version == 'v1':
        return 'qeltrix-2.py', version 
        
    raise ValueError(f"Unsupported Qeltrix version '{version}' detected in file.")

# === MAIN EXECUTION LOGIC ===

if __name__ == "__main__":
    
    if len(sys.argv) < 2:
        print("Usage: python qltx.py <command> [args...]", file=sys.stderr)
        sys.exit(1)
        
    command = sys.argv[1].lower()
    args_to_pass = sys.argv[1:] 
    
    try:
        script_file = None
        version = None
        
        if command == "pack":
            script_file, version = get_script_and_version_for_pack(sys.argv[2:])
            
        elif command in ["unpack", "seek"]:
            if len(sys.argv) < 3:
                raise ValueError(f"Command '{command}' requires an input file.")
            qltx_file = sys.argv[2] 
            script_file, version = get_script_and_version_for_decode(command, qltx_file)
            
        else:
            raise ValueError(f"Unknown Qeltrix command: {command}")

        script_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_file)

        if not os.path.exists(script_file_path):
            raise FileNotFoundError(f"Backend script '{script_file}' not found.")
            
        full_command = [sys.executable, script_file_path] + args_to_pass
        
        print(f"--- Qeltrix Dispatcher ---\nCommand: {command.upper()}, Detected/Target Version: {version.upper()}\nDispatching to: {os.path.basename(script_file)}\n--------------------------", file=sys.stderr)

        result = subprocess.run(full_command, check=False)
        sys.exit(result.returncode)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
